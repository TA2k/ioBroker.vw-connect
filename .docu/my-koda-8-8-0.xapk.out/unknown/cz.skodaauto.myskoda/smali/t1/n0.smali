.class public final Lt1/n0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final g:Lt1/n0;


# instance fields
.field public final a:Lay0/k;

.field public final b:Lay0/k;

.field public final c:Lay0/k;

.field public final d:Lay0/k;

.field public final e:Lay0/k;

.field public final f:Lay0/k;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lt1/n0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/16 v2, 0x3f

    .line 5
    .line 6
    invoke-direct {v0, v1, v1, v1, v2}, Lt1/n0;-><init>(Lay0/k;Lay0/k;Lay0/k;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lt1/n0;->g:Lt1/n0;

    .line 10
    .line 11
    return-void
.end method

.method public synthetic constructor <init>(Lay0/k;Lay0/k;Lay0/k;I)V
    .locals 9

    and-int/lit8 v0, p4, 0x1

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    move-object v3, v1

    goto :goto_0

    :cond_0
    move-object v3, p1

    :goto_0
    and-int/lit8 p1, p4, 0x2

    if-eqz p1, :cond_1

    move-object v4, v1

    goto :goto_1

    :cond_1
    move-object v4, p2

    :goto_1
    and-int/lit8 p1, p4, 0x10

    if-eqz p1, :cond_2

    move-object v7, v1

    goto :goto_2

    :cond_2
    move-object v7, p3

    :goto_2
    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v8, 0x0

    move-object v2, p0

    .line 1
    invoke-direct/range {v2 .. v8}, Lt1/n0;-><init>(Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;)V

    return-void
.end method

.method public constructor <init>(Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lt1/n0;->a:Lay0/k;

    .line 4
    iput-object p2, p0, Lt1/n0;->b:Lay0/k;

    .line 5
    iput-object p3, p0, Lt1/n0;->c:Lay0/k;

    .line 6
    iput-object p4, p0, Lt1/n0;->d:Lay0/k;

    .line 7
    iput-object p5, p0, Lt1/n0;->e:Lay0/k;

    .line 8
    iput-object p6, p0, Lt1/n0;->f:Lay0/k;

    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lt1/n0;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lt1/n0;

    .line 12
    .line 13
    iget-object v1, p1, Lt1/n0;->a:Lay0/k;

    .line 14
    .line 15
    iget-object v3, p0, Lt1/n0;->a:Lay0/k;

    .line 16
    .line 17
    if-ne v3, v1, :cond_2

    .line 18
    .line 19
    iget-object v1, p0, Lt1/n0;->b:Lay0/k;

    .line 20
    .line 21
    iget-object v3, p1, Lt1/n0;->b:Lay0/k;

    .line 22
    .line 23
    if-ne v1, v3, :cond_2

    .line 24
    .line 25
    iget-object v1, p0, Lt1/n0;->c:Lay0/k;

    .line 26
    .line 27
    iget-object v3, p1, Lt1/n0;->c:Lay0/k;

    .line 28
    .line 29
    if-ne v1, v3, :cond_2

    .line 30
    .line 31
    iget-object v1, p0, Lt1/n0;->d:Lay0/k;

    .line 32
    .line 33
    iget-object v3, p1, Lt1/n0;->d:Lay0/k;

    .line 34
    .line 35
    if-ne v1, v3, :cond_2

    .line 36
    .line 37
    iget-object v1, p0, Lt1/n0;->e:Lay0/k;

    .line 38
    .line 39
    iget-object v3, p1, Lt1/n0;->e:Lay0/k;

    .line 40
    .line 41
    if-ne v1, v3, :cond_2

    .line 42
    .line 43
    iget-object p0, p0, Lt1/n0;->f:Lay0/k;

    .line 44
    .line 45
    iget-object p1, p1, Lt1/n0;->f:Lay0/k;

    .line 46
    .line 47
    if-ne p0, p1, :cond_2

    .line 48
    .line 49
    return v0

    .line 50
    :cond_2
    return v2
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object v1, p0, Lt1/n0;->a:Lay0/k;

    .line 3
    .line 4
    if-eqz v1, :cond_0

    .line 5
    .line 6
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    move v1, v0

    .line 12
    :goto_0
    mul-int/lit8 v1, v1, 0x1f

    .line 13
    .line 14
    iget-object v2, p0, Lt1/n0;->b:Lay0/k;

    .line 15
    .line 16
    if-eqz v2, :cond_1

    .line 17
    .line 18
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    goto :goto_1

    .line 23
    :cond_1
    move v2, v0

    .line 24
    :goto_1
    add-int/2addr v1, v2

    .line 25
    mul-int/lit8 v1, v1, 0x1f

    .line 26
    .line 27
    iget-object v2, p0, Lt1/n0;->c:Lay0/k;

    .line 28
    .line 29
    if-eqz v2, :cond_2

    .line 30
    .line 31
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 32
    .line 33
    .line 34
    move-result v2

    .line 35
    goto :goto_2

    .line 36
    :cond_2
    move v2, v0

    .line 37
    :goto_2
    add-int/2addr v1, v2

    .line 38
    mul-int/lit8 v1, v1, 0x1f

    .line 39
    .line 40
    iget-object v2, p0, Lt1/n0;->d:Lay0/k;

    .line 41
    .line 42
    if-eqz v2, :cond_3

    .line 43
    .line 44
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 45
    .line 46
    .line 47
    move-result v2

    .line 48
    goto :goto_3

    .line 49
    :cond_3
    move v2, v0

    .line 50
    :goto_3
    add-int/2addr v1, v2

    .line 51
    mul-int/lit8 v1, v1, 0x1f

    .line 52
    .line 53
    iget-object v2, p0, Lt1/n0;->e:Lay0/k;

    .line 54
    .line 55
    if-eqz v2, :cond_4

    .line 56
    .line 57
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 58
    .line 59
    .line 60
    move-result v2

    .line 61
    goto :goto_4

    .line 62
    :cond_4
    move v2, v0

    .line 63
    :goto_4
    add-int/2addr v1, v2

    .line 64
    mul-int/lit8 v1, v1, 0x1f

    .line 65
    .line 66
    iget-object p0, p0, Lt1/n0;->f:Lay0/k;

    .line 67
    .line 68
    if-eqz p0, :cond_5

    .line 69
    .line 70
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 71
    .line 72
    .line 73
    move-result v0

    .line 74
    :cond_5
    add-int/2addr v1, v0

    .line 75
    return v1
.end method
