.class public final Lq6/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lm6/g;


# instance fields
.field public final a:Lm6/g;


# direct methods
.method public constructor <init>(Lm6/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lq6/c;->a:Lm6/g;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 3

    .line 1
    new-instance v0, Landroidx/lifecycle/n0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x1

    .line 5
    invoke-direct {v0, p1, v1, v2}, Landroidx/lifecycle/n0;-><init>(Lay0/n;Lkotlin/coroutines/Continuation;I)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lq6/c;->a:Lm6/g;

    .line 9
    .line 10
    invoke-interface {p0, v0, p2}, Lm6/g;->a(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method public final getData()Lyy0/i;
    .locals 0

    .line 1
    iget-object p0, p0, Lq6/c;->a:Lm6/g;

    .line 2
    .line 3
    invoke-interface {p0}, Lm6/g;->getData()Lyy0/i;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
