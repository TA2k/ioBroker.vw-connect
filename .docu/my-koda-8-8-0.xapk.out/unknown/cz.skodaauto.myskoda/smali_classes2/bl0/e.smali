.class public final Lbl0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final c:Lbl0/e;

.field public static final d:Lbl0/e;

.field public static final e:Lbl0/e;

.field public static final f:Lbl0/e;


# instance fields
.field public final a:Lbl0/g;

.field public final b:Lbl0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lbl0/e;

    .line 2
    .line 3
    sget-object v1, Lbl0/g;->e:Lbl0/g;

    .line 4
    .line 5
    sget-object v2, Lbl0/g;->f:Lbl0/g;

    .line 6
    .line 7
    invoke-direct {v0, v1, v2}, Lbl0/e;-><init>(Lbl0/g;Lbl0/g;)V

    .line 8
    .line 9
    .line 10
    sput-object v0, Lbl0/e;->c:Lbl0/e;

    .line 11
    .line 12
    new-instance v0, Lbl0/e;

    .line 13
    .line 14
    sget-object v3, Lbl0/g;->g:Lbl0/g;

    .line 15
    .line 16
    invoke-direct {v0, v2, v3}, Lbl0/e;-><init>(Lbl0/g;Lbl0/g;)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Lbl0/e;->d:Lbl0/e;

    .line 20
    .line 21
    new-instance v0, Lbl0/e;

    .line 22
    .line 23
    sget-object v2, Lbl0/g;->h:Lbl0/g;

    .line 24
    .line 25
    invoke-direct {v0, v3, v2}, Lbl0/e;-><init>(Lbl0/g;Lbl0/g;)V

    .line 26
    .line 27
    .line 28
    sput-object v0, Lbl0/e;->e:Lbl0/e;

    .line 29
    .line 30
    new-instance v0, Lbl0/e;

    .line 31
    .line 32
    invoke-direct {v0, v1, v2}, Lbl0/e;-><init>(Lbl0/g;Lbl0/g;)V

    .line 33
    .line 34
    .line 35
    sput-object v0, Lbl0/e;->f:Lbl0/e;

    .line 36
    .line 37
    return-void
.end method

.method public constructor <init>(Lbl0/g;Lbl0/g;)V
    .locals 1

    .line 1
    const-string v0, "from"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "to"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lbl0/e;->a:Lbl0/g;

    .line 15
    .line 16
    iput-object p2, p0, Lbl0/e;->b:Lbl0/g;

    .line 17
    .line 18
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
    instance-of v1, p1, Lbl0/e;

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
    check-cast p1, Lbl0/e;

    .line 12
    .line 13
    iget-object v1, p0, Lbl0/e;->a:Lbl0/g;

    .line 14
    .line 15
    iget-object v3, p1, Lbl0/e;->a:Lbl0/g;

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-object p0, p0, Lbl0/e;->b:Lbl0/g;

    .line 21
    .line 22
    iget-object p1, p1, Lbl0/e;->b:Lbl0/g;

    .line 23
    .line 24
    if-eq p0, p1, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    return v0
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget-object v0, p0, Lbl0/e;->a:Lbl0/g;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-object p0, p0, Lbl0/e;->b:Lbl0/g;

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    add-int/2addr p0, v0

    .line 16
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "ChargingPower(from="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lbl0/e;->a:Lbl0/g;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", to="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object p0, p0, Lbl0/e;->b:Lbl0/g;

    .line 19
    .line 20
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string p0, ")"

    .line 24
    .line 25
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0
.end method
