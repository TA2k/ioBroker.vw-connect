.class public final Le71/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/compose/ui/input/pointer/PointerInputEventHandler;


# instance fields
.field public final synthetic d:Lay0/a;

.field public final synthetic e:Lay0/a;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Ll2/b1;

.field public final synthetic h:Ll2/b1;


# direct methods
.method public constructor <init>(Lay0/a;Lay0/a;Lay0/a;Ll2/b1;Ll2/b1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Le71/f;->d:Lay0/a;

    .line 5
    .line 6
    iput-object p2, p0, Le71/f;->e:Lay0/a;

    .line 7
    .line 8
    iput-object p3, p0, Le71/f;->f:Lay0/a;

    .line 9
    .line 10
    iput-object p4, p0, Le71/f;->g:Ll2/b1;

    .line 11
    .line 12
    iput-object p5, p0, Le71/f;->h:Ll2/b1;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Lp3/x;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 7

    .line 1
    new-instance v0, Le71/e;

    .line 2
    .line 3
    iget-object v5, p0, Le71/f;->h:Ll2/b1;

    .line 4
    .line 5
    const/4 v6, 0x0

    .line 6
    iget-object v1, p0, Le71/f;->d:Lay0/a;

    .line 7
    .line 8
    iget-object v2, p0, Le71/f;->e:Lay0/a;

    .line 9
    .line 10
    iget-object v3, p0, Le71/f;->f:Lay0/a;

    .line 11
    .line 12
    iget-object v4, p0, Le71/f;->g:Ll2/b1;

    .line 13
    .line 14
    invoke-direct/range {v0 .. v6}, Le71/e;-><init>(Lay0/a;Lay0/a;Lay0/a;Ll2/b1;Ll2/b1;Lkotlin/coroutines/Continuation;)V

    .line 15
    .line 16
    .line 17
    const/4 p0, 0x0

    .line 18
    const/16 v1, 0xb

    .line 19
    .line 20
    invoke-static {p1, v0, p0, p2, v1}, Lg1/g3;->e(Lp3/x;Lay0/o;Lay0/k;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 25
    .line 26
    if-ne p0, p1, :cond_0

    .line 27
    .line 28
    return-object p0

    .line 29
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    return-object p0
.end method
