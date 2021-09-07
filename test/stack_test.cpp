// Copyright (c) 2021, Jiang Yinzuo. All rights reserved.

#include "art/stack.h"
#include "gtest/gtest.h"

namespace {

TEST(StackTest, PushPop) {
    art_stack stack;
    art_stack_init(&stack);
    art_stack_push(&stack, 'x');
    ASSERT_EQ(stack.items, 1);
    ASSERT_EQ(art_stack_peek(&stack), 'x');
    ASSERT_EQ(stack.items, 1);
    ASSERT_EQ(art_stack_pop(&stack), 'x');
    ASSERT_EQ(stack.items, 0);
    art_stack_free(&stack);
}

} // namespace