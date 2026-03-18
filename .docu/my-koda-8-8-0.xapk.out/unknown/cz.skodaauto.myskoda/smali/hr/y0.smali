.class public final Lhr/y0;
.super Lhr/h0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic f:Lhr/z0;


# direct methods
.method public constructor <init>(Lhr/z0;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lhr/y0;->f:Lhr/z0;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/util/AbstractCollection;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final get(I)Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object p0, p0, Lhr/y0;->f:Lhr/z0;

    .line 2
    .line 3
    iget v0, p0, Lhr/z0;->i:I

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkp/i9;->d(II)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lhr/z0;->h:[Ljava/lang/Object;

    .line 9
    .line 10
    mul-int/lit8 p1, p1, 0x2

    .line 11
    .line 12
    aget-object v0, p0, p1

    .line 13
    .line 14
    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    add-int/lit8 p1, p1, 0x1

    .line 18
    .line 19
    aget-object p0, p0, p1

    .line 20
    .line 21
    invoke-static {p0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    new-instance p1, Ljava/util/AbstractMap$SimpleImmutableEntry;

    .line 25
    .line 26
    invoke-direct {p1, v0, p0}, Ljava/util/AbstractMap$SimpleImmutableEntry;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    return-object p1
.end method

.method public final m()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public final size()I
    .locals 0

    .line 1
    iget-object p0, p0, Lhr/y0;->f:Lhr/z0;

    .line 2
    .line 3
    iget p0, p0, Lhr/z0;->i:I

    .line 4
    .line 5
    return p0
.end method
