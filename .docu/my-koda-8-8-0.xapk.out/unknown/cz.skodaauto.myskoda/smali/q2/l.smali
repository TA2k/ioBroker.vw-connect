.class public final Lq2/l;
.super Lq2/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lj3/f0;


# direct methods
.method public constructor <init>(Lj3/f0;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, v0}, Lq2/j;-><init>(I)V

    .line 3
    .line 4
    .line 5
    iput-object p1, p0, Lq2/l;->h:Lj3/f0;

    .line 6
    .line 7
    return-void
.end method


# virtual methods
.method public final next()Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lq2/j;->g:I

    .line 2
    .line 3
    add-int/lit8 v1, v0, 0x2

    .line 4
    .line 5
    iput v1, p0, Lq2/j;->g:I

    .line 6
    .line 7
    new-instance v1, Lq2/a;

    .line 8
    .line 9
    iget-object v2, p0, Lq2/j;->e:[Ljava/lang/Object;

    .line 10
    .line 11
    aget-object v3, v2, v0

    .line 12
    .line 13
    add-int/lit8 v0, v0, 0x1

    .line 14
    .line 15
    aget-object v0, v2, v0

    .line 16
    .line 17
    iget-object p0, p0, Lq2/l;->h:Lj3/f0;

    .line 18
    .line 19
    invoke-direct {v1, p0, v3, v0}, Lq2/a;-><init>(Lj3/f0;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    return-object v1
.end method
