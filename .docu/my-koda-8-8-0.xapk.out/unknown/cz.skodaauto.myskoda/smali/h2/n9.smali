.class public final Lh2/n9;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/compose/ui/input/pointer/PointerInputEventHandler;


# instance fields
.field public final synthetic d:Lh2/u7;

.field public final synthetic e:Li1/l;

.field public final synthetic f:Li1/l;


# direct methods
.method public constructor <init>(Lh2/u7;Li1/l;Li1/l;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/n9;->d:Lh2/u7;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/n9;->e:Li1/l;

    .line 7
    .line 8
    iput-object p3, p0, Lh2/n9;->f:Li1/l;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Lp3/x;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    new-instance v4, Lgw0/c;

    .line 2
    .line 3
    iget-object v0, p0, Lh2/n9;->f:Li1/l;

    .line 4
    .line 5
    const/16 v1, 0x18

    .line 6
    .line 7
    iget-object v3, p0, Lh2/n9;->d:Lh2/u7;

    .line 8
    .line 9
    iget-object p0, p0, Lh2/n9;->e:Li1/l;

    .line 10
    .line 11
    invoke-direct {v4, v3, p0, v0, v1}, Lgw0/c;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 12
    .line 13
    .line 14
    new-instance v0, La7/k;

    .line 15
    .line 16
    const/4 v5, 0x0

    .line 17
    const/16 v1, 0x1a

    .line 18
    .line 19
    move-object v2, p1

    .line 20
    invoke-direct/range {v0 .. v5}, La7/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 21
    .line 22
    .line 23
    invoke-static {v0, p2}, Lvy0/e0;->o(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    if-ne p0, p1, :cond_0

    .line 30
    .line 31
    return-object p0

    .line 32
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    return-object p0
.end method
