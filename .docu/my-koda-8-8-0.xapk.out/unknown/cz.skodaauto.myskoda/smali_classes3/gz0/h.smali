.class public final Lgz0/h;
.super Lgz0/d;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lqz0/g;
    with = Lmz0/j;
.end annotation


# static fields
.field public static final Companion:Lgz0/g;


# instance fields
.field public final b:I


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lgz0/g;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lgz0/h;->Companion:Lgz0/g;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>(I)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lgz0/h;->b:I

    .line 5
    .line 6
    if-lez p1, :cond_0

    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    const-string p0, "Unit duration must be positive, but was "

    .line 10
    .line 11
    const-string v0, " months."

    .line 12
    .line 13
    invoke-static {p0, p1, v0}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 18
    .line 19
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    throw p1
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    if-eq p0, p1, :cond_1

    .line 2
    .line 3
    instance-of v0, p1, Lgz0/h;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    check-cast p1, Lgz0/h;

    .line 8
    .line 9
    iget p1, p1, Lgz0/h;->b:I

    .line 10
    .line 11
    iget p0, p0, Lgz0/h;->b:I

    .line 12
    .line 13
    if-ne p0, p1, :cond_0

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    const/4 p0, 0x0

    .line 17
    return p0

    .line 18
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 19
    return p0
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget p0, p0, Lgz0/h;->b:I

    .line 2
    .line 3
    const/high16 v0, 0x20000

    .line 4
    .line 5
    xor-int/2addr p0, v0

    .line 6
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    .line 1
    iget p0, p0, Lgz0/h;->b:I

    .line 2
    .line 3
    rem-int/lit16 v0, p0, 0x4b0

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    div-int/lit16 p0, p0, 0x4b0

    .line 8
    .line 9
    const-string v0, "CENTURY"

    .line 10
    .line 11
    invoke-static {p0, v0}, Lgz0/k;->a(ILjava/lang/String;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0

    .line 16
    :cond_0
    rem-int/lit8 v0, p0, 0xc

    .line 17
    .line 18
    if-nez v0, :cond_1

    .line 19
    .line 20
    div-int/lit8 p0, p0, 0xc

    .line 21
    .line 22
    const-string v0, "YEAR"

    .line 23
    .line 24
    invoke-static {p0, v0}, Lgz0/k;->a(ILjava/lang/String;)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0

    .line 29
    :cond_1
    rem-int/lit8 v0, p0, 0x3

    .line 30
    .line 31
    if-nez v0, :cond_2

    .line 32
    .line 33
    div-int/lit8 p0, p0, 0x3

    .line 34
    .line 35
    const-string v0, "QUARTER"

    .line 36
    .line 37
    invoke-static {p0, v0}, Lgz0/k;->a(ILjava/lang/String;)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    return-object p0

    .line 42
    :cond_2
    const-string v0, "MONTH"

    .line 43
    .line 44
    invoke-static {p0, v0}, Lgz0/k;->a(ILjava/lang/String;)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0
.end method
