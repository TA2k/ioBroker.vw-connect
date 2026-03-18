.class public final Lv3/n0;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic f:Lv3/p0;

.field public final synthetic g:J

.field public final synthetic h:J

.field public final synthetic i:Lv3/s1;


# direct methods
.method public constructor <init>(Lv3/p0;JJLv3/s1;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lv3/n0;->f:Lv3/p0;

    .line 2
    .line 3
    iput-wide p2, p0, Lv3/n0;->g:J

    .line 4
    .line 5
    iput-wide p4, p0, Lv3/n0;->h:J

    .line 6
    .line 7
    iput-object p6, p0, Lv3/n0;->i:Lv3/s1;

    .line 8
    .line 9
    const/4 p1, 0x0

    .line 10
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lv3/n0;->f:Lv3/p0;

    .line 2
    .line 3
    invoke-virtual {v0}, Lv3/p0;->Q0()Lv3/m0;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    const/4 v2, 0x0

    .line 8
    iput-boolean v2, v1, Lv3/m0;->d:Z

    .line 9
    .line 10
    invoke-virtual {v0}, Lv3/p0;->Q0()Lv3/m0;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    iget-wide v2, p0, Lv3/n0;->g:J

    .line 15
    .line 16
    iput-wide v2, v1, Lv3/m0;->e:J

    .line 17
    .line 18
    invoke-virtual {v0}, Lv3/p0;->Q0()Lv3/m0;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    iget-wide v2, p0, Lv3/n0;->h:J

    .line 23
    .line 24
    iput-wide v2, v1, Lv3/m0;->f:J

    .line 25
    .line 26
    iget-object p0, p0, Lv3/n0;->i:Lv3/s1;

    .line 27
    .line 28
    iget-object p0, p0, Lv3/s1;->d:Lt3/r0;

    .line 29
    .line 30
    invoke-interface {p0}, Lt3/r0;->d()Lay0/k;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    if-eqz p0, :cond_0

    .line 35
    .line 36
    invoke-virtual {v0}, Lv3/p0;->Q0()Lv3/m0;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 44
    .line 45
    return-object p0
.end method
