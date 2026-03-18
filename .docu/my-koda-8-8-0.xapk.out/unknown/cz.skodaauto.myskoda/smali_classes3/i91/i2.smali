.class public final Li91/i2;
.super Lx2/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/p;


# instance fields
.field public final r:J

.field public final s:Li1/l;

.field public final t:Lc1/c;


# direct methods
.method public constructor <init>(JLi1/l;)V
    .locals 1

    .line 1
    const-string v0, "interactionSource"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Lx2/r;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-wide p1, p0, Li91/i2;->r:J

    .line 10
    .line 11
    iput-object p3, p0, Li91/i2;->s:Li1/l;

    .line 12
    .line 13
    const/4 p1, 0x0

    .line 14
    invoke-static {p1}, Lc1/d;->a(F)Lc1/c;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    iput-object p1, p0, Li91/i2;->t:Lc1/c;

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final C0(Lv3/j0;)V
    .locals 14

    .line 1
    iget-object v0, p1, Lv3/j0;->d:Lg3/b;

    .line 2
    .line 3
    iget-object v1, v0, Lg3/b;->e:Lgw0/c;

    .line 4
    .line 5
    invoke-virtual {v1}, Lgw0/c;->h()Le3/r;

    .line 6
    .line 7
    .line 8
    iget-wide v1, p0, Li91/i2;->r:J

    .line 9
    .line 10
    invoke-static {v1, v2}, Le3/s;->d(J)F

    .line 11
    .line 12
    .line 13
    move-result v3

    .line 14
    iget-object p0, p0, Li91/i2;->t:Lc1/c;

    .line 15
    .line 16
    invoke-virtual {p0}, Lc1/c;->d()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    check-cast p0, Ljava/lang/Number;

    .line 21
    .line 22
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    mul-float/2addr p0, v3

    .line 27
    invoke-static {v1, v2, p0}, Le3/s;->b(JF)J

    .line 28
    .line 29
    .line 30
    move-result-wide v4

    .line 31
    invoke-interface {v0}, Lg3/d;->e()J

    .line 32
    .line 33
    .line 34
    move-result-wide v8

    .line 35
    const/4 v12, 0x0

    .line 36
    const/16 v13, 0x7a

    .line 37
    .line 38
    const-wide/16 v6, 0x0

    .line 39
    .line 40
    const/4 v10, 0x0

    .line 41
    const/4 v11, 0x0

    .line 42
    move-object v3, p1

    .line 43
    invoke-static/range {v3 .. v13}, Lg3/d;->r0(Lg3/d;JJJFLg3/h;Le3/m;I)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {v3}, Lv3/j0;->b()V

    .line 47
    .line 48
    .line 49
    return-void
.end method

.method public final P0()V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lx2/r;->L0()Lvy0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, Lh40/h;

    .line 6
    .line 7
    const/16 v2, 0x11

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    invoke-direct {v1, p0, v3, v2}, Lh40/h;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 11
    .line 12
    .line 13
    const/4 p0, 0x3

    .line 14
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public final m0()V
    .locals 0

    .line 1
    return-void
.end method
