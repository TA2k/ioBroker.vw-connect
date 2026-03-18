.class public final Lwz0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/CharSequence;


# instance fields
.field public final d:[C

.field public e:I


# direct methods
.method public constructor <init>([C)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lwz0/c;->d:[C

    .line 5
    .line 6
    array-length p1, p1

    .line 7
    iput p1, p0, Lwz0/c;->e:I

    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final charAt(I)C
    .locals 0

    .line 1
    iget-object p0, p0, Lwz0/c;->d:[C

    .line 2
    .line 3
    aget-char p0, p0, p1

    .line 4
    .line 5
    return p0
.end method

.method public final length()I
    .locals 0

    .line 1
    iget p0, p0, Lwz0/c;->e:I

    .line 2
    .line 3
    return p0
.end method

.method public final subSequence(II)Ljava/lang/CharSequence;
    .locals 1

    .line 1
    iget v0, p0, Lwz0/c;->e:I

    .line 2
    .line 3
    invoke-static {p2, v0}, Ljava/lang/Math;->min(II)I

    .line 4
    .line 5
    .line 6
    move-result p2

    .line 7
    iget-object p0, p0, Lwz0/c;->d:[C

    .line 8
    .line 9
    invoke-static {p0, p1, p2}, Lly0/w;->k([CII)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    iget v0, p0, Lwz0/c;->e:I

    .line 2
    .line 3
    iget-object p0, p0, Lwz0/c;->d:[C

    .line 4
    .line 5
    invoke-static {v0, v0}, Ljava/lang/Math;->min(II)I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/4 v1, 0x0

    .line 10
    invoke-static {p0, v1, v0}, Lly0/w;->k([CII)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method
