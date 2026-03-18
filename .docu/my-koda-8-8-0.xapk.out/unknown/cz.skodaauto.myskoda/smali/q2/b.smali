.class public Lq2/b;
.super Lmx0/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final f:Lq2/b;


# instance fields
.field public final d:Lq2/i;

.field public final e:I


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lq2/b;

    .line 2
    .line 3
    sget-object v1, Lq2/i;->e:Lq2/i;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Lq2/b;-><init>(Lq2/i;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lq2/b;->f:Lq2/b;

    .line 10
    .line 11
    return-void
.end method

.method public constructor <init>(Lq2/i;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lq2/b;->d:Lq2/i;

    .line 5
    .line 6
    iput p2, p0, Lq2/b;->e:I

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a()Ljava/util/Set;
    .locals 2

    .line 1
    new-instance v0, Lq2/g;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, p0, v1}, Lq2/g;-><init>(Lq2/b;I)V

    .line 5
    .line 6
    .line 7
    return-object v0
.end method

.method public final b()Ljava/util/Set;
    .locals 2

    .line 1
    new-instance v0, Lq2/g;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, p0, v1}, Lq2/g;-><init>(Lq2/b;I)V

    .line 5
    .line 6
    .line 7
    return-object v0
.end method

.method public final c()I
    .locals 0

    .line 1
    iget p0, p0, Lq2/b;->e:I

    .line 2
    .line 3
    return p0
.end method

.method public containsKey(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p1, :cond_0

    .line 3
    .line 4
    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    .line 5
    .line 6
    .line 7
    move-result v1

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move v1, v0

    .line 10
    :goto_0
    iget-object p0, p0, Lq2/b;->d:Lq2/i;

    .line 11
    .line 12
    invoke-virtual {p0, v1, p1, v0}, Lq2/i;->d(ILjava/lang/Object;I)Z

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    return p0
.end method

.method public final d()Ljava/util/Collection;
    .locals 2

    .line 1
    new-instance v0, Lly0/k;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, p0, v1}, Lly0/k;-><init>(Ljava/lang/Object;I)V

    .line 5
    .line 6
    .line 7
    return-object v0
.end method

.method public final e(Ljava/lang/Object;Lr2/a;)Lq2/b;
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p1, :cond_0

    .line 3
    .line 4
    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    .line 5
    .line 6
    .line 7
    move-result v1

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move v1, v0

    .line 10
    :goto_0
    iget-object v2, p0, Lq2/b;->d:Lq2/i;

    .line 11
    .line 12
    invoke-virtual {v2, v1, v0, p1, p2}, Lq2/i;->u(IILjava/lang/Object;Ljava/lang/Object;)Lb11/a;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    if-nez p1, :cond_1

    .line 17
    .line 18
    return-object p0

    .line 19
    :cond_1
    new-instance p2, Lq2/b;

    .line 20
    .line 21
    iget-object v0, p1, Lb11/a;->f:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v0, Lq2/i;

    .line 24
    .line 25
    iget p0, p0, Lq2/b;->e:I

    .line 26
    .line 27
    iget p1, p1, Lb11/a;->e:I

    .line 28
    .line 29
    add-int/2addr p0, p1

    .line 30
    invoke-direct {p2, v0, p0}, Lq2/b;-><init>(Lq2/i;I)V

    .line 31
    .line 32
    .line 33
    return-object p2
.end method

.method public get(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p1, :cond_0

    .line 3
    .line 4
    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    .line 5
    .line 6
    .line 7
    move-result v1

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move v1, v0

    .line 10
    :goto_0
    iget-object p0, p0, Lq2/b;->d:Lq2/i;

    .line 11
    .line 12
    invoke-virtual {p0, v1, p1, v0}, Lq2/i;->g(ILjava/lang/Object;I)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method
