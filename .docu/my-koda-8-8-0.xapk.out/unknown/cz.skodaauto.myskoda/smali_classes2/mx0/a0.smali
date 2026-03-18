.class public final Lmx0/a0;
.super Lmx0/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:I

.field public e:I

.field public final synthetic f:Lmx0/b0;


# direct methods
.method public constructor <init>(Lmx0/b0;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lmx0/a0;->f:Lmx0/b0;

    .line 5
    .line 6
    iget v0, p1, Lmx0/b0;->g:I

    .line 7
    .line 8
    iput v0, p0, Lmx0/a0;->d:I

    .line 9
    .line 10
    iget p1, p1, Lmx0/b0;->f:I

    .line 11
    .line 12
    iput p1, p0, Lmx0/a0;->e:I

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final computeNext()V
    .locals 3

    .line 1
    iget v0, p0, Lmx0/a0;->d:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lmx0/b;->done()V

    .line 6
    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    iget-object v0, p0, Lmx0/a0;->f:Lmx0/b0;

    .line 10
    .line 11
    iget-object v1, v0, Lmx0/b0;->d:[Ljava/lang/Object;

    .line 12
    .line 13
    iget v2, p0, Lmx0/a0;->e:I

    .line 14
    .line 15
    aget-object v1, v1, v2

    .line 16
    .line 17
    invoke-virtual {p0, v1}, Lmx0/b;->setNext(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    iget v1, p0, Lmx0/a0;->e:I

    .line 21
    .line 22
    add-int/lit8 v1, v1, 0x1

    .line 23
    .line 24
    iget v0, v0, Lmx0/b0;->e:I

    .line 25
    .line 26
    rem-int/2addr v1, v0

    .line 27
    iput v1, p0, Lmx0/a0;->e:I

    .line 28
    .line 29
    iget v0, p0, Lmx0/a0;->d:I

    .line 30
    .line 31
    add-int/lit8 v0, v0, -0x1

    .line 32
    .line 33
    iput v0, p0, Lmx0/a0;->d:I

    .line 34
    .line 35
    return-void
.end method
