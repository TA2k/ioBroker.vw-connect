.class public final Lr1/c;
.super Le1/v;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public O:Z

.field public P:Lay0/k;

.field public final Q:Lr1/b;


# direct methods
.method public constructor <init>(ZLi1/l;ZZLd4/i;Lay0/k;)V
    .locals 8

    .line 1
    new-instance v7, Lal/s;

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    invoke-direct {v7, v0, p6, p1}, Lal/s;-><init>(ILay0/k;Z)V

    .line 5
    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    const/4 v5, 0x0

    .line 9
    move-object v0, p0

    .line 10
    move-object v1, p2

    .line 11
    move v3, p3

    .line 12
    move v4, p4

    .line 13
    move-object v6, p5

    .line 14
    invoke-direct/range {v0 .. v7}, Le1/h;-><init>(Li1/l;Le1/s0;ZZLjava/lang/String;Ld4/i;Lay0/a;)V

    .line 15
    .line 16
    .line 17
    iput-boolean p1, v0, Lr1/c;->O:Z

    .line 18
    .line 19
    iput-object p6, v0, Lr1/c;->P:Lay0/k;

    .line 20
    .line 21
    new-instance p0, Lr1/b;

    .line 22
    .line 23
    const/4 p1, 0x0

    .line 24
    invoke-direct {p0, v0, p1}, Lr1/b;-><init>(Ljava/lang/Object;I)V

    .line 25
    .line 26
    .line 27
    iput-object p0, v0, Lr1/c;->Q:Lr1/b;

    .line 28
    .line 29
    return-void
.end method


# virtual methods
.method public final a1(Ld4/l;)V
    .locals 3

    .line 1
    iget-boolean p0, p0, Lr1/c;->O:Z

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    sget-object p0, Lf4/a;->d:Lf4/a;

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    sget-object p0, Lf4/a;->e:Lf4/a;

    .line 9
    .line 10
    :goto_0
    sget-object v0, Ld4/x;->a:[Lhy0/z;

    .line 11
    .line 12
    sget-object v0, Ld4/v;->I:Ld4/z;

    .line 13
    .line 14
    sget-object v1, Ld4/x;->a:[Lhy0/z;

    .line 15
    .line 16
    const/16 v2, 0x18

    .line 17
    .line 18
    aget-object v1, v1, v2

    .line 19
    .line 20
    invoke-virtual {v0, p1, p0}, Ld4/z;->a(Ld4/l;Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    return-void
.end method
