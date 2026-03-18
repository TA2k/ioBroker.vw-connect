.class public final Lt1/d1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/compose/ui/input/pointer/PointerInputEventHandler;


# instance fields
.field public final synthetic d:Lvy0/b0;

.field public final synthetic e:Ll2/b1;

.field public final synthetic f:Li1/l;

.field public final synthetic g:Ll2/b1;


# direct methods
.method public constructor <init>(Lvy0/b0;Ll2/b1;Li1/l;Ll2/b1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lt1/d1;->d:Lvy0/b0;

    .line 5
    .line 6
    iput-object p2, p0, Lt1/d1;->e:Ll2/b1;

    .line 7
    .line 8
    iput-object p3, p0, Lt1/d1;->f:Li1/l;

    .line 9
    .line 10
    iput-object p4, p0, Lt1/d1;->g:Ll2/b1;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Lp3/x;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    new-instance v2, Lt1/c1;

    .line 2
    .line 3
    iget-object v0, p0, Lt1/d1;->f:Li1/l;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    iget-object v3, p0, Lt1/d1;->d:Lvy0/b0;

    .line 7
    .line 8
    iget-object v4, p0, Lt1/d1;->e:Ll2/b1;

    .line 9
    .line 10
    invoke-direct {v2, v3, v4, v0, v1}, Lt1/c1;-><init>(Lvy0/b0;Ll2/b1;Li1/l;Lkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    new-instance v3, Lle/b;

    .line 14
    .line 15
    const/16 v0, 0xc

    .line 16
    .line 17
    iget-object p0, p0, Lt1/d1;->g:Ll2/b1;

    .line 18
    .line 19
    invoke-direct {v3, p0, v0}, Lle/b;-><init>(Ll2/b1;I)V

    .line 20
    .line 21
    .line 22
    sget-object p0, Lg1/g3;->a:Lg1/e1;

    .line 23
    .line 24
    new-instance v4, Lg1/z1;

    .line 25
    .line 26
    const/4 p0, 0x0

    .line 27
    invoke-direct {v4, p1, p0}, Lg1/z1;-><init>(Lt4/c;I)V

    .line 28
    .line 29
    .line 30
    new-instance v0, Laa/i0;

    .line 31
    .line 32
    const/4 v5, 0x0

    .line 33
    move-object v1, p1

    .line 34
    invoke-direct/range {v0 .. v5}, Laa/i0;-><init>(Lp3/x;Lay0/o;Lay0/k;Lg1/z1;Lkotlin/coroutines/Continuation;)V

    .line 35
    .line 36
    .line 37
    invoke-static {v0, p2}, Lvy0/e0;->o(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 42
    .line 43
    sget-object p2, Llx0/b0;->a:Llx0/b0;

    .line 44
    .line 45
    if-ne p0, p1, :cond_0

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_0
    move-object p0, p2

    .line 49
    :goto_0
    if-ne p0, p1, :cond_1

    .line 50
    .line 51
    return-object p0

    .line 52
    :cond_1
    return-object p2
.end method
