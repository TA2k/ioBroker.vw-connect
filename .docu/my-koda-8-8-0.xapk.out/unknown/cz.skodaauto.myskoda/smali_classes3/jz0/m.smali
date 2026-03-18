.class public abstract Ljz0/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljz0/j;


# instance fields
.field public final a:Ljz0/u;

.field public final b:Ljava/util/List;

.field public final c:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljz0/u;Ljava/util/List;Ljava/lang/String;)V
    .locals 1

    .line 1
    const-string v0, "field"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Ljz0/m;->a:Ljz0/u;

    .line 10
    .line 11
    iput-object p2, p0, Ljz0/m;->b:Ljava/util/List;

    .line 12
    .line 13
    iput-object p3, p0, Ljz0/m;->c:Ljava/lang/String;

    .line 14
    .line 15
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    iget p3, p1, Ljz0/u;->c:I

    .line 20
    .line 21
    iget p1, p1, Ljz0/u;->b:I

    .line 22
    .line 23
    sub-int/2addr p3, p1

    .line 24
    add-int/lit8 p3, p3, 0x1

    .line 25
    .line 26
    if-ne p0, p3, :cond_0

    .line 27
    .line 28
    return-void

    .line 29
    :cond_0
    new-instance p0, Ljava/lang/StringBuilder;

    .line 30
    .line 31
    const-string p1, "The number of values ("

    .line 32
    .line 33
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 37
    .line 38
    .line 39
    move-result p1

    .line 40
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string p1, ") in "

    .line 44
    .line 45
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    const-string p1, " does not match the range of the field ("

    .line 52
    .line 53
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    const/16 p1, 0x29

    .line 57
    .line 58
    invoke-static {p0, p3, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->m(Ljava/lang/StringBuilder;IC)Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 63
    .line 64
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    throw p1
.end method


# virtual methods
.method public final a()Lkz0/c;
    .locals 1

    .line 1
    new-instance p0, Lkz0/a;

    .line 2
    .line 3
    new-instance v0, Lio/ktor/utils/io/g0;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-object p0
.end method

.method public final b()Llz0/n;
    .locals 7

    .line 1
    new-instance v0, Llz0/n;

    .line 2
    .line 3
    new-instance v1, Llz0/s;

    .line 4
    .line 5
    iget-object v2, p0, Ljz0/m;->b:Ljava/util/List;

    .line 6
    .line 7
    move-object v3, v2

    .line 8
    check-cast v3, Ljava/util/Collection;

    .line 9
    .line 10
    new-instance v4, Lhu/q;

    .line 11
    .line 12
    const/16 v5, 0x9

    .line 13
    .line 14
    invoke-direct {v4, p0, v5}, Lhu/q;-><init>(Ljava/lang/Object;I)V

    .line 15
    .line 16
    .line 17
    new-instance v5, Ljava/lang/StringBuilder;

    .line 18
    .line 19
    const-string v6, "one of "

    .line 20
    .line 21
    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    const-string v2, " for "

    .line 28
    .line 29
    invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    iget-object p0, p0, Ljz0/m;->c:Ljava/lang/String;

    .line 33
    .line 34
    invoke-virtual {v5, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-direct {v1, v3, v4, p0}, Llz0/s;-><init>(Ljava/util/Collection;Lhu/q;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    invoke-static {v1}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 49
    .line 50
    invoke-direct {v0, p0, v1}, Llz0/n;-><init>(Ljava/util/List;Ljava/util/List;)V

    .line 51
    .line 52
    .line 53
    return-object v0
.end method

.method public final bridge synthetic c()Ljz0/a;
    .locals 0

    .line 1
    iget-object p0, p0, Ljz0/m;->a:Ljz0/u;

    .line 2
    .line 3
    return-object p0
.end method
