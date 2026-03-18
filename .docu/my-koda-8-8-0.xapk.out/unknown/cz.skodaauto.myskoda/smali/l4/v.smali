.class public final Ll4/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final d:Lu2/l;


# instance fields
.field public final a:Lg4/g;

.field public final b:J

.field public final c:Lg4/o0;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Ll20/f;

    .line 2
    .line 3
    const/4 v1, 0x7

    .line 4
    invoke-direct {v0, v1}, Ll20/f;-><init>(I)V

    .line 5
    .line 6
    .line 7
    new-instance v1, Lkq0/a;

    .line 8
    .line 9
    const/4 v2, 0x5

    .line 10
    invoke-direct {v1, v2}, Lkq0/a;-><init>(I)V

    .line 11
    .line 12
    .line 13
    new-instance v2, Lu2/l;

    .line 14
    .line 15
    invoke-direct {v2, v0, v1}, Lu2/l;-><init>(Lay0/n;Lay0/k;)V

    .line 16
    .line 17
    .line 18
    sput-object v2, Ll4/v;->d:Lu2/l;

    .line 19
    .line 20
    return-void
.end method

.method public constructor <init>(JLjava/lang/String;I)V
    .locals 1

    and-int/lit8 v0, p4, 0x1

    if-eqz v0, :cond_0

    .line 10
    const-string p3, ""

    :cond_0
    and-int/lit8 p4, p4, 0x2

    if-eqz p4, :cond_1

    .line 11
    sget-wide p1, Lg4/o0;->b:J

    :cond_1
    const/4 p4, 0x0

    .line 12
    invoke-direct {p0, p3, p1, p2, p4}, Ll4/v;-><init>(Ljava/lang/String;JLg4/o0;)V

    return-void
.end method

.method public constructor <init>(Lg4/g;JLg4/o0;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Ll4/v;->a:Lg4/g;

    .line 3
    iget-object v0, p1, Lg4/g;->e:Ljava/lang/String;

    .line 4
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    move-result v0

    invoke-static {v0, p2, p3}, Lg4/f0;->c(IJ)J

    move-result-wide p2

    iput-wide p2, p0, Ll4/v;->b:J

    if-eqz p4, :cond_0

    .line 5
    iget-wide p2, p4, Lg4/o0;->a:J

    .line 6
    iget-object p1, p1, Lg4/g;->e:Ljava/lang/String;

    .line 7
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result p1

    invoke-static {p1, p2, p3}, Lg4/f0;->c(IJ)J

    move-result-wide p1

    .line 8
    new-instance p3, Lg4/o0;

    invoke-direct {p3, p1, p2}, Lg4/o0;-><init>(J)V

    goto :goto_0

    :cond_0
    const/4 p3, 0x0

    .line 9
    :goto_0
    iput-object p3, p0, Ll4/v;->c:Lg4/o0;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;JLg4/o0;)V
    .locals 1

    .line 13
    new-instance v0, Lg4/g;

    invoke-direct {v0, p1}, Lg4/g;-><init>(Ljava/lang/String;)V

    invoke-direct {p0, v0, p2, p3, p4}, Ll4/v;-><init>(Lg4/g;JLg4/o0;)V

    return-void
.end method

.method public static a(Ll4/v;Lg4/g;JI)Ll4/v;
    .locals 1

    .line 1
    and-int/lit8 v0, p4, 0x1

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Ll4/v;->a:Lg4/g;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 v0, p4, 0x2

    .line 8
    .line 9
    if-eqz v0, :cond_1

    .line 10
    .line 11
    iget-wide p2, p0, Ll4/v;->b:J

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p4, p4, 0x4

    .line 14
    .line 15
    if-eqz p4, :cond_2

    .line 16
    .line 17
    iget-object p4, p0, Ll4/v;->c:Lg4/o0;

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_2
    const/4 p4, 0x0

    .line 21
    :goto_0
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    new-instance p0, Ll4/v;

    .line 25
    .line 26
    invoke-direct {p0, p1, p2, p3, p4}, Ll4/v;-><init>(Lg4/g;JLg4/o0;)V

    .line 27
    .line 28
    .line 29
    return-object p0
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 7

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Ll4/v;

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
    check-cast p1, Ll4/v;

    .line 12
    .line 13
    iget-wide v3, p1, Ll4/v;->b:J

    .line 14
    .line 15
    iget-wide v5, p0, Ll4/v;->b:J

    .line 16
    .line 17
    invoke-static {v5, v6, v3, v4}, Lg4/o0;->b(JJ)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_2

    .line 22
    .line 23
    iget-object v1, p0, Ll4/v;->c:Lg4/o0;

    .line 24
    .line 25
    iget-object v3, p1, Ll4/v;->c:Lg4/o0;

    .line 26
    .line 27
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    if-eqz v1, :cond_2

    .line 32
    .line 33
    iget-object p0, p0, Ll4/v;->a:Lg4/g;

    .line 34
    .line 35
    iget-object p1, p1, Ll4/v;->a:Lg4/g;

    .line 36
    .line 37
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result p0

    .line 41
    if-eqz p0, :cond_2

    .line 42
    .line 43
    return v0

    .line 44
    :cond_2
    return v2
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Ll4/v;->a:Lg4/g;

    .line 2
    .line 3
    invoke-virtual {v0}, Lg4/g;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    sget v2, Lg4/o0;->c:I

    .line 11
    .line 12
    iget-wide v2, p0, Ll4/v;->b:J

    .line 13
    .line 14
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    iget-object p0, p0, Ll4/v;->c:Lg4/o0;

    .line 19
    .line 20
    if-eqz p0, :cond_0

    .line 21
    .line 22
    iget-wide v1, p0, Lg4/o0;->a:J

    .line 23
    .line 24
    invoke-static {v1, v2}, Ljava/lang/Long;->hashCode(J)I

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    const/4 p0, 0x0

    .line 30
    :goto_0
    add-int/2addr v0, p0

    .line 31
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "TextFieldValue(text=\'"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Ll4/v;->a:Lg4/g;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, "\', selection="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-wide v1, p0, Ll4/v;->b:J

    .line 19
    .line 20
    invoke-static {v1, v2}, Lg4/o0;->h(J)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    const-string v1, ", composition="

    .line 28
    .line 29
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    iget-object p0, p0, Ll4/v;->c:Lg4/o0;

    .line 33
    .line 34
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    const/16 p0, 0x29

    .line 38
    .line 39
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0
.end method
