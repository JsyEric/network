#!/bin/bash

pkill -9 sr_solution
pkill -9 sr_solution_macm
pkill -9 sr
pgrep pox | xargs kill -9
pgrep mininet | xargs kill -9
