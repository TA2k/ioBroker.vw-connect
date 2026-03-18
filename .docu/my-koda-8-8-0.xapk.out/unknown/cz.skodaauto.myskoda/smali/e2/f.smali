.class public final synthetic Le2/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:J

.field public final synthetic e:Lay0/a;

.field public final synthetic f:Z


# direct methods
.method public synthetic constructor <init>(JLay0/a;Z)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Le2/f;->d:J

    .line 5
    .line 6
    iput-object p3, p0, Le2/f;->e:Lay0/a;

    .line 7
    .line 8
    iput-boolean p4, p0, Le2/f;->f:Z

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    check-cast p1, Lb3/d;

    .line 2
    .line 3
    iget-object v0, p1, Lb3/d;->d:Lb3/b;

    .line 4
    .line 5
    invoke-interface {v0}, Lb3/b;->e()J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    const/16 v2, 0x20

    .line 10
    .line 11
    shr-long/2addr v0, v2

    .line 12
    long-to-int v0, v0

    .line 13
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    const/high16 v1, 0x40000000    # 2.0f

    .line 18
    .line 19
    div-float/2addr v0, v1

    .line 20
    invoke-static {p1, v0}, Lkp/o;->d(Lb3/d;F)Le3/f;

    .line 21
    .line 22
    .line 23
    move-result-object v4

    .line 24
    new-instance v5, Le3/m;

    .line 25
    .line 26
    iget-wide v0, p0, Le2/f;->d:J

    .line 27
    .line 28
    const/4 v2, 0x5

    .line 29
    invoke-direct {v5, v0, v1, v2}, Le3/m;-><init>(JI)V

    .line 30
    .line 31
    .line 32
    new-instance v1, Le2/g;

    .line 33
    .line 34
    const/4 v6, 0x0

    .line 35
    iget-object v2, p0, Le2/f;->e:Lay0/a;

    .line 36
    .line 37
    iget-boolean v3, p0, Le2/f;->f:Z

    .line 38
    .line 39
    invoke-direct/range {v1 .. v6}, Le2/g;-><init>(Ljava/lang/Object;ZLjava/lang/Object;Ljava/lang/Object;I)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {p1, v1}, Lb3/d;->b(Lay0/k;)Lb3/g;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0
.end method
