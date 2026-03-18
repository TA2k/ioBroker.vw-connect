.class public final Lv3/s0;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic f:Lv3/u0;

.field public final synthetic g:J


# direct methods
.method public constructor <init>(Lv3/u0;J)V
    .locals 0

    .line 1
    iput-object p1, p0, Lv3/s0;->f:Lv3/u0;

    .line 2
    .line 3
    iput-wide p2, p0, Lv3/s0;->g:J

    .line 4
    .line 5
    const/4 p1, 0x0

    .line 6
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 3

    .line 1
    iget-object v0, p0, Lv3/s0;->f:Lv3/u0;

    .line 2
    .line 3
    iget-object v0, v0, Lv3/u0;->i:Lv3/l0;

    .line 4
    .line 5
    invoke-virtual {v0}, Lv3/l0;->a()Lv3/f1;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-virtual {v0}, Lv3/f1;->d1()Lv3/q0;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    iget-wide v1, p0, Lv3/s0;->g:J

    .line 17
    .line 18
    invoke-interface {v0, v1, v2}, Lt3/p0;->L(J)Lt3/e1;

    .line 19
    .line 20
    .line 21
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 22
    .line 23
    return-object p0
.end method
