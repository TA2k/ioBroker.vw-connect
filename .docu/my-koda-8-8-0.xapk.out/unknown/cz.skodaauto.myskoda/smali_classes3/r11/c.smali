.class public final Lr11/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lr11/y;
.implements Lr11/w;


# instance fields
.field public final d:C


# direct methods
.method public constructor <init>(C)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-char p1, p0, Lr11/c;->d:C

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a()I
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public final b(Ljava/lang/StringBuilder;JLjp/u1;ILn11/f;Ljava/util/Locale;)V
    .locals 0

    .line 1
    iget-char p0, p0, Lr11/c;->d:C

    .line 2
    .line 3
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/Appendable;

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final c(Ljava/lang/StringBuilder;Lo11/b;Ljava/util/Locale;)V
    .locals 0

    .line 1
    iget-char p0, p0, Lr11/c;->d:C

    .line 2
    .line 3
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/Appendable;

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final d(Lr11/s;Ljava/lang/CharSequence;I)I
    .locals 0

    .line 1
    invoke-interface {p2}, Ljava/lang/CharSequence;->length()I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    if-lt p3, p1, :cond_0

    .line 6
    .line 7
    not-int p0, p3

    .line 8
    return p0

    .line 9
    :cond_0
    invoke-interface {p2, p3}, Ljava/lang/CharSequence;->charAt(I)C

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    iget-char p0, p0, Lr11/c;->d:C

    .line 14
    .line 15
    if-eq p1, p0, :cond_1

    .line 16
    .line 17
    invoke-static {p1}, Ljava/lang/Character;->toUpperCase(C)C

    .line 18
    .line 19
    .line 20
    move-result p1

    .line 21
    invoke-static {p0}, Ljava/lang/Character;->toUpperCase(C)C

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    if-eq p1, p0, :cond_1

    .line 26
    .line 27
    invoke-static {p1}, Ljava/lang/Character;->toLowerCase(C)C

    .line 28
    .line 29
    .line 30
    move-result p1

    .line 31
    invoke-static {p0}, Ljava/lang/Character;->toLowerCase(C)C

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    if-eq p1, p0, :cond_1

    .line 36
    .line 37
    not-int p0, p3

    .line 38
    return p0

    .line 39
    :cond_1
    add-int/lit8 p3, p3, 0x1

    .line 40
    .line 41
    return p3
.end method

.method public final e()I
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method
