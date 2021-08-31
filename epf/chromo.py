import sys
from typing import Dict, Any, Callable, Union, Tuple

from . import constants
from scapy.fields import Field, PacketListField
from scapy.all import rdpcap
from scapy.packet import Packet
import uuid
from numpy import random
import random as stdrandom
from uuid import UUID


from .transition_payload import TransitionGraph


class Chromosome(object):
    def __init__(self, individual: "Individual", field: Field, packet: Packet):
        self._field = field
        self._individual = individual
        self._pkt = packet

    @property
    def name(self):
        return self._field.name

    @property
    def original_value(self) -> Any:
        return self._field.default

    @property
    def current_value(self) -> Any:
        return self._pkt.getfieldval(self._field.name)

    @current_value.setter
    def current_value(self, val: Any):
        self._pkt.setfieldval(self._field.name, val)

    def reset_value(self) -> Any:
        self._pkt.setfieldval(self._field.name, self.original_value)
        return self._field.default

    def random_mutate(self):
        # we can't mutate non-primitives.. randomly choose one within the nested structure and mutate that instead
        field = self._field
        layer = self._pkt
        if isinstance(self._field, PacketListField):
            layer = self._pkt.getlayer(1)
            field = layer.get_field(random.choice(layer.fields_desc).name)
            if constants.TRACE:
                print(f"rng_trace, random_mutate, 1, {field.name}", file=sys.stderr)
        randval = field.randval()
        if randval is not None:
            val = randval._fix()
            layer.setfieldval(field.name, val)
            if constants.TRACE:
                print(f"rng_trace, random_mutate, 2, {val}", file=sys.stderr)
            sys.stderr.flush()
        # # we can't mutate non-primitives.. randomly choose one within the nested structure and mutate that instead
        # field = self._field
        # layer = self._pkt
        # if isinstance(self._field, PacketListField):
        #     layer = self._pkt.getlayer(1)
        #     field = layer.get_field(random.choice(layer.fields_desc).name)
        # randval = field.randval()
        # if isinstance(field, ASN1F_BIT_STRING):
        #     b = layer.getfieldval(field.name)
        #     if not isinstance(b, str):
        #         b = layer.getfieldval(field.name).val
        #     randval = RandString(size=len(b), chars=b'01')._fix().decode('ascii')
        # elif randval is not None:
        #     randval = randval._fix()
        # if randval is not None:
        #     layer.setfieldval(field.name, randval)


class Individual(object):
    def __init__(self, packet: Packet, parents: Union[Tuple[UUID, UUID], Tuple[None, None]] = (None, None)):
        self._pkt = packet
        self._chromosomes = self._build_chromosomes()
        self._identifier = uuid.UUID(int=stdrandom.getrandbits(128))
        if constants.TRACE:
            print(f"rng_trace, Individual(), 1, {self._identifier}", file=sys.stderr)
        self._parents = parents
        self.testcase = None
        self.index = -1
        self._species = None
        self.seed_corpus = False

    def _mix_genes_on_birth(self, genetics: Dict[str, Chromosome]):
        for name, chromo in genetics.items():
            self._chromosomes[name].current_value = chromo.current_value

    def _build_chromosomes(self) -> Dict[str, Chromosome]:
        chromos = dict()
        for name, field in sorted(self._pkt.fieldtype.items()):
            chromos[name] = (Chromosome(self, field, self._pkt))
        return chromos

    def random_mutation(self):
        keys = sorted(set(self._chromosomes))
        mutation_field = random.choice(keys)
        if constants.TRACE:
            print(f"rng_trace, random_mutation, 1, {mutation_field}", file=sys.stderr)
        self._chromosomes[mutation_field].random_mutate()

    def give_birth(self, other_parent: "Individual", genetics: Dict[str, Chromosome]) -> "Individual":
        pkt = self._pkt.copy()
        child = Individual(pkt, parents=(self.identity, other_parent.identity))
        child.species = self.species
        child._mix_genes_on_birth(genetics)
        return child

    @property
    def parents(self) -> Union[Tuple[UUID, UUID], Tuple[None, None]]:
        return self._parents

    @property
    def identity(self):
        return self._identifier

    @property
    def species(self) -> str:
        return self._pkt.name if self._species is None else self._species

    @species.setter
    def species(self, value: Union[str, None]) -> None:
        self._species = value

    @property
    def chromosomes(self) -> Dict[str, Chromosome]:
        return self._chromosomes

    def serialize(self) -> bytes:
        return bytes(self._pkt)

    def compatible(self, other: "Individual") -> bool:
        return all([set(self.chromosomes) == set(other.chromosomes), self.species == other.species])

    def identical(self, other: "Individual") -> bool:
        if not self.compatible(other):
            return False
        chromo_other = other.chromosomes
        return all(v.current_value == chromo_other[k].current_value for k, v in self.chromosomes.items())


class Crossover:

    @staticmethod
    def single_point(a: Dict[str, Chromosome], b: Dict[str, Chromosome]) -> Dict[str, Chromosome]:
        c = {}
        keys = sorted(set(a))
        point = random.randint(0, len(keys))
        if constants.TRACE:
            print(f"rng_trace, single_point, 1, {point}", file=sys.stderr)
        for k in keys[:point]:
            c[k] = a[k]
        for k in keys[point:]:
            c[k] = b[k]
        return c


class Population(object):
    def __init__(self,
                 crossover_fn: Callable[[Dict[str, Chromosome], Dict[str, Chromosome]],
                                        Dict[str, Chromosome]] = Crossover.single_point,
                 p_mutation: float = 0.8):
        self._p_mutation = p_mutation
        self._seed_pop = []
        self._crossover = crossover_fn
        self._pop_by_id = {}
        self._pop = []
        self.crossovers = 0
        self.spot_mutations = 0
        self.recv_after_send = False
        self._stateg = TransitionGraph(self)

    @property
    def state_graph(self) -> TransitionGraph:
        return self._stateg

    def update(self, child: Individual, heat: float = 1.0, add: bool = False):
        identical = any(o.identical(child) for o in self._pop)
        if identical:
            return
        parents = []
        for pid in child.parents:
            if pid in self._pop_by_id:
                parents += [self._pop_by_id[pid]]
        if child.testcase.coverage_increase:
            # interesting child, prioritize it
            for i, p in enumerate(parents):
                # increase probability of parents to be chosen by moving them up in the order
                new_idx = min(0, p.index - 1)
                #if i == 0 and len(parents) == 2 and p.index < parents[i + 1].index and new_idx >= parents[i+1].index:
                if i == 0 and len(parents) == 2 and p.index < parents[i + 1].index and new_idx >= parents[i + 1].index:
                    parents[i + 1].index -= 1
                self._pop.pop(p.index)
                self._pop.insert(new_idx, p)
            self._pop.insert(0, child)
            self._pop_by_id[child.identity] = child
            return
        for i, p in enumerate(parents):
            # increase probability of parents to be chosen by moving them up in the order
            new_idx = p.index + 1
            if i == 0 and len(parents) == 2 and p.index < parents[i + 1].index and new_idx >= parents[i + 1].index:
                parents[i + 1].index -= 1
            self._pop.pop(p.index)
            self._pop.insert(new_idx, p)
        if add:
            # simulated annealing decided to add it either ways...we put the child somewhere based in the heat
            new_idx = int((1 - heat) * len(self._pop))
            self._pop.insert(new_idx, child)
            self._pop_by_id[child.identity] = child

    def shrink(self, size: int):
        if size == 0 or size >= len(self._pop):
            return
        dying = self._pop.pop(len(self._pop) - 1)
        if dying.identity in self._pop_by_id:
            del self._pop_by_id[dying.identity]

    @property
    def species(self):
        return self._pop[0].species if len(self._pop) > 0 else ""

    def add(self, individual: Individual, seed_corpus=True) -> bool:
        same_species = len(self._pop) == 0 or self._pop[0].compatible(individual)
        identical = any(o.identical(individual) for o in self._pop)
        if same_species and not identical:
            self._pop.append(individual)
            self._pop_by_id[individual.identity] = individual
            if seed_corpus:
                individual.seed_corpus = True
                self._seed_pop += [individual]
        return same_species

    def new_child(self):
        a_sampler = Population.truncated_uniform_choice
        b_sampler = Population.truncated_uniform_choice
        rng = random.random()
        if constants.TRACE:
            print(f"rng_trace, single_point, 1, {rng}", file=sys.stderr)
        if rng <= 0.5:
            a_sampler = Population.truncated_exp_choice
        else:
            b_sampler = Population.truncated_exp_choice
        a, a_idx = a_sampler(self._pop)
        b, b_idx = (a, a_idx)
        while b == a:
            b, b_idx = b_sampler(self._pop)
        a.index = a_idx
        b.index = b_idx
        # mix chromosomes
        child_chromos = self._crossover(a.chromosomes, b.chromosomes)
        self.crossovers += 1
        # give birth
        c = a.give_birth(b, child_chromos)
        rng = random.random()
        if constants.TRACE:
            print(f"rng_trace, new_child, 2, {rng}", file=sys.stderr)
        if rng <= self._p_mutation:
            self.spot_mutations += 1
            c.random_mutation()
        return c

    def shuffle(self):
        if constants.TRACE:
            print(f"rng_trace, shuffle, 1, -", file=sys.stderr)
        random.shuffle(self._pop)

    def reseed(self, shrink_size: int):
        for seed_indiv in self._seed_pop:
            try:
                self._pop.remove(seed_indiv)
            except ValueError:
                pass
            self._pop.insert(0, seed_indiv)
        self.shrink(shrink_size)
        for idx, indiv in enumerate(self._pop):
            indiv.index = idx

    def __iter__(self):
        return iter(self._pop)

    def __len__(self) -> int:
        return len(self._pop)

    @staticmethod
    def truncated_exp_choice(pop):
        x = len(pop) + 1
        while x >= len(pop):
            x = random.exponential() * len(pop)
            if constants.TRACE:
                print(f"rng_trace, truncated_exp_choice, 1, {x}", file=sys.stderr)
        return pop[int(x)], int(x)

    @staticmethod
    def truncated_uniform_choice(pop):
        x = random.randint(low=0, high=len(pop), dtype=int)
        if constants.TRACE:
            print(f"rng_trace, truncated_uniform_choice, 1, {x}", file=sys.stderr)
        return pop[x], x


    @staticmethod
    def generate(pcap_filename: str,
                 layer_filter: Callable[[Packet], Union[Packet, None]] = lambda x: x,
                 population_identifier: Callable[[Packet], str] = lambda x: x.name,
                 population_crossover_operator: Callable[[Dict[str, Chromosome], Dict[str, Chromosome]],
                                                         Dict[str, Chromosome]] = Crossover.single_point,
                 population_mutation_probability: float = 0.8,
                 ) -> Dict[str, "Population"]:
        pkts = rdpcap(pcap_filename)
        populations = {}
        for pkt in pkts:
            stripped = layer_filter(pkt)
            if stripped is None:
                continue
            indiv = Individual(stripped)
            species = population_identifier(stripped)
            indiv.species = species
            if indiv.species not in populations:
                populations[indiv.species] = Population(
                    crossover_fn=population_crossover_operator,
                    p_mutation=population_mutation_probability,
                )
            populations[indiv.species].add(indiv, seed_corpus=True)
        for pop in populations.values():
            pop.shuffle()
        # assert that each population has >= two individuals:
        for pop in populations.values():
            if len(pop) < 2:
                clone = Individual(pop._pop[0]._pkt.copy())
                clone.species = pop.species
                n = stdrandom.randint(1, len(clone.chromosomes))
                if constants.TRACE:
                    print(f"rng_trace, generate, 1, {n}", file=sys.stderr)
                for i in range(1, n):
                    clone.random_mutation()
                pop.add(clone)
        return populations

