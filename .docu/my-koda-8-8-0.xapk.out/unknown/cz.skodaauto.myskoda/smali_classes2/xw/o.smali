.class public final Lxw/o;
.super Lxw/u;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:I

.field public final c:I


# direct methods
.method public constructor <init>(Ljava/lang/String;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lxw/o;->a:Ljava/lang/String;

    .line 5
    .line 6
    iput p2, p0, Lxw/o;->b:I

    .line 7
    .line 8
    iput p3, p0, Lxw/o;->c:I

    .line 9
    .line 10
    return-void
.end method

.method public static b(Ljava/lang/String;ZZ)I
    .locals 8

    .line 1
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-eqz p1, :cond_0

    .line 7
    .line 8
    move v2, v1

    .line 9
    goto :goto_0

    .line 10
    :cond_0
    add-int/lit8 v2, v0, -0x1

    .line 11
    .line 12
    :goto_0
    const/4 v3, -0x1

    .line 13
    if-eqz p1, :cond_1

    .line 14
    .line 15
    goto :goto_1

    .line 16
    :cond_1
    move v0, v3

    .line 17
    :goto_1
    const/4 v4, 0x1

    .line 18
    if-eqz p1, :cond_2

    .line 19
    .line 20
    move v5, v4

    .line 21
    goto :goto_2

    .line 22
    :cond_2
    move v5, v3

    .line 23
    :goto_2
    if-eq v2, v0, :cond_6

    .line 24
    .line 25
    invoke-virtual {p0, v2}, Ljava/lang/String;->charAt(I)C

    .line 26
    .line 27
    .line 28
    move-result v6

    .line 29
    const/16 v7, 0xa

    .line 30
    .line 31
    if-ne v6, v7, :cond_4

    .line 32
    .line 33
    if-eqz p1, :cond_3

    .line 34
    .line 35
    return v2

    .line 36
    :cond_3
    add-int/2addr v2, v4

    .line 37
    return v2

    .line 38
    :cond_4
    invoke-static {v6}, Ljava/lang/Character;->isWhitespace(C)Z

    .line 39
    .line 40
    .line 41
    move-result v6

    .line 42
    if-nez v6, :cond_5

    .line 43
    .line 44
    goto :goto_3

    .line 45
    :cond_5
    add-int/2addr v2, v5

    .line 46
    goto :goto_2

    .line 47
    :cond_6
    if-nez p1, :cond_8

    .line 48
    .line 49
    if-nez p2, :cond_7

    .line 50
    .line 51
    goto :goto_3

    .line 52
    :cond_7
    return v1

    .line 53
    :cond_8
    :goto_3
    return v3
.end method


# virtual methods
.method public final a(Lxw/v;Lxw/s;Ljava/io/StringWriter;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lxw/o;->a:Ljava/lang/String;

    .line 2
    .line 3
    :try_start_0
    invoke-virtual {p3, p0}, Ljava/io/Writer;->write(Ljava/lang/String;)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 4
    .line 5
    .line 6
    return-void

    .line 7
    :catch_0
    move-exception p0

    .line 8
    new-instance p1, La8/r0;

    .line 9
    .line 10
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 11
    .line 12
    .line 13
    throw p1
.end method

.method public final c()Lxw/o;
    .locals 4

    .line 1
    iget v0, p0, Lxw/o;->b:I

    .line 2
    .line 3
    const/4 v1, -0x1

    .line 4
    if-ne v0, v1, :cond_0

    .line 5
    .line 6
    return-object p0

    .line 7
    :cond_0
    add-int/lit8 v0, v0, 0x1

    .line 8
    .line 9
    iget v2, p0, Lxw/o;->c:I

    .line 10
    .line 11
    if-ne v2, v1, :cond_1

    .line 12
    .line 13
    move v2, v1

    .line 14
    goto :goto_0

    .line 15
    :cond_1
    sub-int/2addr v2, v0

    .line 16
    :goto_0
    new-instance v3, Lxw/o;

    .line 17
    .line 18
    iget-object p0, p0, Lxw/o;->a:Ljava/lang/String;

    .line 19
    .line 20
    invoke-virtual {p0, v0}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-direct {v3, p0, v1, v2}, Lxw/o;-><init>(Ljava/lang/String;II)V

    .line 25
    .line 26
    .line 27
    return-object v3
.end method

.method public final d()Lxw/o;
    .locals 5

    .line 1
    iget v0, p0, Lxw/o;->c:I

    .line 2
    .line 3
    const/4 v1, -0x1

    .line 4
    if-ne v0, v1, :cond_0

    .line 5
    .line 6
    return-object p0

    .line 7
    :cond_0
    new-instance v2, Lxw/o;

    .line 8
    .line 9
    iget-object v3, p0, Lxw/o;->a:Ljava/lang/String;

    .line 10
    .line 11
    const/4 v4, 0x0

    .line 12
    invoke-virtual {v3, v4, v0}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    iget p0, p0, Lxw/o;->b:I

    .line 17
    .line 18
    invoke-direct {v2, v0, p0, v1}, Lxw/o;-><init>(Ljava/lang/String;II)V

    .line 19
    .line 20
    .line 21
    return-object v2
.end method

.method public final toString()Ljava/lang/String;
    .locals 4

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "Text("

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string v1, "\r"

    .line 9
    .line 10
    const-string v2, "\\r"

    .line 11
    .line 12
    iget-object v3, p0, Lxw/o;->a:Ljava/lang/String;

    .line 13
    .line 14
    invoke-virtual {v3, v1, v2}, Ljava/lang/String;->replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    const-string v2, "\n"

    .line 19
    .line 20
    const-string v3, "\\n"

    .line 21
    .line 22
    invoke-virtual {v1, v2, v3}, Ljava/lang/String;->replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    const-string v1, ")"

    .line 30
    .line 31
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    iget v1, p0, Lxw/o;->b:I

    .line 35
    .line 36
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    const-string v1, "/"

    .line 40
    .line 41
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    iget p0, p0, Lxw/o;->c:I

    .line 45
    .line 46
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    return-object p0
.end method
