.class public final Lr4/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final c:Lr4/i;


# instance fields
.field public final a:F

.field public final b:I


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lr4/i;

    .line 2
    .line 3
    sget v1, Lr4/f;->c:F

    .line 4
    .line 5
    const/16 v2, 0x11

    .line 6
    .line 7
    invoke-direct {v0, v2, v1}, Lr4/i;-><init>(IF)V

    .line 8
    .line 9
    .line 10
    sput-object v0, Lr4/i;->c:Lr4/i;

    .line 11
    .line 12
    return-void
.end method

.method public constructor <init>(IF)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p2, p0, Lr4/i;->a:F

    .line 5
    .line 6
    iput p1, p0, Lr4/i;->b:I

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lr4/i;

    .line 6
    .line 7
    if-nez v1, :cond_1

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_1
    check-cast p1, Lr4/i;

    .line 11
    .line 12
    iget v1, p1, Lr4/i;->a:F

    .line 13
    .line 14
    sget v2, Lr4/f;->b:F

    .line 15
    .line 16
    iget v2, p0, Lr4/i;->a:F

    .line 17
    .line 18
    invoke-static {v2, v1}, Ljava/lang/Float;->compare(FF)I

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-nez v1, :cond_2

    .line 23
    .line 24
    iget p0, p0, Lr4/i;->b:I

    .line 25
    .line 26
    iget p1, p1, Lr4/i;->b:I

    .line 27
    .line 28
    if-ne p0, p1, :cond_2

    .line 29
    .line 30
    return v0

    .line 31
    :cond_2
    :goto_0
    const/4 p0, 0x0

    .line 32
    return p0
.end method

.method public final hashCode()I
    .locals 2

    .line 1
    sget v0, Lr4/f;->b:F

    .line 2
    .line 3
    iget v0, p0, Lr4/i;->a:F

    .line 4
    .line 5
    invoke-static {v0}, Ljava/lang/Float;->hashCode(F)I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/16 v1, 0x1f

    .line 10
    .line 11
    mul-int/2addr v0, v1

    .line 12
    iget p0, p0, Lr4/i;->b:I

    .line 13
    .line 14
    invoke-static {p0, v0, v1}, Lc1/j0;->g(III)I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    const/4 v0, 0x0

    .line 19
    invoke-static {v0}, Ljava/lang/Integer;->hashCode(I)I

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    add-int/2addr v0, p0

    .line 24
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "LineHeightStyle(alignment="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget v1, p0, Lr4/i;->a:F

    .line 9
    .line 10
    invoke-static {v1}, Lr4/f;->b(F)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string v1, ", trim="

    .line 18
    .line 19
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    const/4 v1, 0x1

    .line 23
    iget p0, p0, Lr4/i;->b:I

    .line 24
    .line 25
    if-ne p0, v1, :cond_0

    .line 26
    .line 27
    const-string p0, "LineHeightStyle.Trim.FirstLineTop"

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    const/16 v1, 0x10

    .line 31
    .line 32
    if-ne p0, v1, :cond_1

    .line 33
    .line 34
    const-string p0, "LineHeightStyle.Trim.LastLineBottom"

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_1
    const/16 v1, 0x11

    .line 38
    .line 39
    if-ne p0, v1, :cond_2

    .line 40
    .line 41
    const-string p0, "LineHeightStyle.Trim.Both"

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_2
    if-nez p0, :cond_3

    .line 45
    .line 46
    const-string p0, "LineHeightStyle.Trim.None"

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_3
    const-string p0, "Invalid"

    .line 50
    .line 51
    :goto_0
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    const-string p0, ",mode=Mode(value=0))"

    .line 55
    .line 56
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    return-object p0
.end method
