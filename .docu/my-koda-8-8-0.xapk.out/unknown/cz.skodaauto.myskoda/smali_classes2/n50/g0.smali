.class public final Ln50/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/i;


# instance fields
.field public final synthetic d:Lyy0/i;

.field public final synthetic e:Z


# direct methods
.method public constructor <init>(Lyy0/i;Z)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ln50/g0;->d:Lyy0/i;

    .line 5
    .line 6
    iput-boolean p2, p0, Ln50/g0;->e:Z

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 3

    .line 1
    new-instance v0, Lc00/g;

    .line 2
    .line 3
    iget-boolean v1, p0, Ln50/g0;->e:Z

    .line 4
    .line 5
    const/4 v2, 0x2

    .line 6
    invoke-direct {v0, p1, v1, v2}, Lc00/g;-><init>(Ljava/lang/Object;ZI)V

    .line 7
    .line 8
    .line 9
    iget-object p0, p0, Ln50/g0;->d:Lyy0/i;

    .line 10
    .line 11
    invoke-interface {p0, v0, p2}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 16
    .line 17
    if-ne p0, p1, :cond_0

    .line 18
    .line 19
    return-object p0

    .line 20
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 21
    .line 22
    return-object p0
.end method
