.class public final Lhr/a1;
.super Lhr/k0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final transient g:Lhr/c1;

.field public final transient h:Lhr/b1;


# direct methods
.method public constructor <init>(Lhr/c1;Lhr/b1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/util/AbstractCollection;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lhr/a1;->g:Lhr/c1;

    .line 5
    .line 6
    iput-object p2, p0, Lhr/a1;->h:Lhr/b1;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final c()Lhr/h0;
    .locals 0

    .line 1
    iget-object p0, p0, Lhr/a1;->h:Lhr/b1;

    .line 2
    .line 3
    return-object p0
.end method

.method public final contains(Ljava/lang/Object;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lhr/a1;->g:Lhr/c1;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lhr/c1;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x1

    .line 10
    return p0

    .line 11
    :cond_0
    const/4 p0, 0x0

    .line 12
    return p0
.end method

.method public final e(I[Ljava/lang/Object;)I
    .locals 0

    .line 1
    iget-object p0, p0, Lhr/a1;->h:Lhr/b1;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lhr/h0;->e(I[Ljava/lang/Object;)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final m()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public final s()Lhr/l1;
    .locals 1

    .line 1
    iget-object p0, p0, Lhr/a1;->h:Lhr/b1;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    invoke-virtual {p0, v0}, Lhr/h0;->s(I)Lhr/f0;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    return-object p0
.end method

.method public final size()I
    .locals 0

    .line 1
    iget-object p0, p0, Lhr/a1;->g:Lhr/c1;

    .line 2
    .line 3
    iget p0, p0, Lhr/c1;->i:I

    .line 4
    .line 5
    return p0
.end method
