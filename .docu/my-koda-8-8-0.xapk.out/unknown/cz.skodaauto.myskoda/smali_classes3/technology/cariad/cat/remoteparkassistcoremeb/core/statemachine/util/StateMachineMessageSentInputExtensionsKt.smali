.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/util/StateMachineMessageSentInputExtensionsKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0005\u001a\u0013\u0010\u0002\u001a\u00020\u0001*\u00020\u0000H\u0000\u00a2\u0006\u0004\u0008\u0002\u0010\u0003\u001a\u0013\u0010\u0002\u001a\u00020\u0001*\u00020\u0004H\u0000\u00a2\u0006\u0004\u0008\u0002\u0010\u0005\"\u001a\u0010\u0008\u001a\u0004\u0018\u00010\u0004*\u00020\u00008@X\u0080\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0006\u0010\u0007\u00a8\u0006\t"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;",
        "Ls71/k;",
        "getTargetScenarioOption",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;)Ls71/k;",
        "Ls71/q;",
        "(Ls71/q;)Ls71/k;",
        "getUserAction",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;)Ls71/q;",
        "userAction",
        "remoteparkassistcoremeb_release"
    }
    k = 0x2
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method public static final getTargetScenarioOption(Ls71/q;)Ls71/k;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    sget-object v0, Ls71/p;->t:Ls71/p;

    if-ne p0, v0, :cond_0

    sget-object p0, Ls71/k;->n:Ls71/k;

    return-object p0

    .line 3
    :cond_0
    sget-object v0, Ls71/p;->j:Ls71/p;

    if-ne p0, v0, :cond_1

    sget-object p0, Ls71/k;->f:Ls71/k;

    return-object p0

    .line 4
    :cond_1
    sget-object v0, Ls71/p;->k:Ls71/p;

    if-ne p0, v0, :cond_2

    sget-object p0, Ls71/k;->g:Ls71/k;

    return-object p0

    .line 5
    :cond_2
    sget-object v0, Ls71/p;->l:Ls71/p;

    if-ne p0, v0, :cond_3

    sget-object p0, Ls71/k;->h:Ls71/k;

    return-object p0

    .line 6
    :cond_3
    sget-object v0, Ls71/p;->m:Ls71/p;

    if-ne p0, v0, :cond_4

    sget-object p0, Ls71/k;->i:Ls71/k;

    return-object p0

    .line 7
    :cond_4
    sget-object v0, Ls71/p;->p:Ls71/p;

    if-ne p0, v0, :cond_5

    sget-object p0, Ls71/k;->j:Ls71/k;

    return-object p0

    .line 8
    :cond_5
    sget-object v0, Ls71/p;->q:Ls71/p;

    if-ne p0, v0, :cond_6

    sget-object p0, Ls71/k;->k:Ls71/k;

    return-object p0

    .line 9
    :cond_6
    sget-object v0, Ls71/p;->r:Ls71/p;

    if-ne p0, v0, :cond_7

    sget-object p0, Ls71/k;->l:Ls71/k;

    return-object p0

    .line 10
    :cond_7
    sget-object v0, Ls71/p;->s:Ls71/p;

    if-ne p0, v0, :cond_8

    sget-object p0, Ls71/k;->m:Ls71/k;

    return-object p0

    .line 11
    :cond_8
    sget-object p0, Ls71/k;->e:Ls71/k;

    return-object p0
.end method

.method public static final getTargetScenarioOption(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;)Ls71/k;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/util/StateMachineMessageSentInputExtensionsKt;->getUserAction(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;)Ls71/q;

    move-result-object p0

    if-nez p0, :cond_0

    sget-object p0, Ls71/p;->d:Ls71/p;

    :cond_0
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/util/StateMachineMessageSentInputExtensionsKt;->getTargetScenarioOption(Ls71/q;)Ls71/k;

    move-result-object p0

    return-object p0
.end method

.method public static final getUserAction(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;)Ls71/q;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;->getData()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    instance-of v0, p0, Lt71/a;

    .line 11
    .line 12
    const/4 v1, 0x0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    check-cast p0, Lt71/a;

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    move-object p0, v1

    .line 19
    :goto_0
    if-eqz p0, :cond_1

    .line 20
    .line 21
    iget-object p0, p0, Lt71/a;->b:Ls71/q;

    .line 22
    .line 23
    return-object p0

    .line 24
    :cond_1
    return-object v1
.end method
