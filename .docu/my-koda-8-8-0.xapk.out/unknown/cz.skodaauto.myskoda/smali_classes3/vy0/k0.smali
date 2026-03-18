.class public final Lvy0/k0;
.super Lrx0/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public synthetic d:Ljava/lang/Object;

.field public e:I


# virtual methods
.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iput-object p1, p0, Lvy0/k0;->d:Ljava/lang/Object;

    .line 2
    .line 3
    iget p1, p0, Lvy0/k0;->e:I

    .line 4
    .line 5
    const/high16 v0, -0x80000000

    .line 6
    .line 7
    or-int/2addr p1, v0

    .line 8
    iput p1, p0, Lvy0/k0;->e:I

    .line 9
    .line 10
    invoke-static {p0}, Lvy0/e0;->h(Lrx0/c;)V

    .line 11
    .line 12
    .line 13
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 14
    .line 15
    return-object p0
.end method
