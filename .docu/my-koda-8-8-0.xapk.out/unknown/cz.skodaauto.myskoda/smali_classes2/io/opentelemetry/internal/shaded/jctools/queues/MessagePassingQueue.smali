.class public interface abstract Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$ExitCondition;,
        Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$WaitStrategy;,
        Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Consumer;,
        Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Supplier;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;"
    }
.end annotation


# static fields
.field public static final UNBOUNDED_CAPACITY:I = -0x1


# virtual methods
.method public abstract capacity()I
.end method

.method public abstract clear()V
.end method

.method public abstract drain(Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Consumer;)I
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Consumer<",
            "TT;>;)I"
        }
    .end annotation
.end method

.method public abstract drain(Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Consumer;I)I
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Consumer<",
            "TT;>;I)I"
        }
    .end annotation
.end method

.method public abstract drain(Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Consumer;Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$WaitStrategy;Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$ExitCondition;)V
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Consumer<",
            "TT;>;",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$WaitStrategy;",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$ExitCondition;",
            ")V"
        }
    .end annotation
.end method

.method public abstract fill(Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Supplier;)I
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Supplier<",
            "TT;>;)I"
        }
    .end annotation
.end method

.method public abstract fill(Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Supplier;I)I
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Supplier<",
            "TT;>;I)I"
        }
    .end annotation
.end method

.method public abstract fill(Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Supplier;Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$WaitStrategy;Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$ExitCondition;)V
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Supplier<",
            "TT;>;",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$WaitStrategy;",
            "Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$ExitCondition;",
            ")V"
        }
    .end annotation
.end method

.method public abstract isEmpty()Z
.end method

.method public abstract offer(Ljava/lang/Object;)Z
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TT;)Z"
        }
    .end annotation
.end method

.method public abstract peek()Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()TT;"
        }
    .end annotation
.end method

.method public abstract poll()Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()TT;"
        }
    .end annotation
.end method

.method public abstract relaxedOffer(Ljava/lang/Object;)Z
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TT;)Z"
        }
    .end annotation
.end method

.method public abstract relaxedPeek()Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()TT;"
        }
    .end annotation
.end method

.method public abstract relaxedPoll()Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()TT;"
        }
    .end annotation
.end method

.method public abstract size()I
.end method
