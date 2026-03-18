.class Lcom/squareup/moshi/CollectionJsonAdapter$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/squareup/moshi/JsonAdapter$Factory;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/squareup/moshi/CollectionJsonAdapter;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/reflect/Type;Ljava/util/Set;Lcom/squareup/moshi/Moshi;)Lcom/squareup/moshi/JsonAdapter;
    .locals 1

    .line 1
    invoke-static {p1}, Lcom/squareup/moshi/Types;->c(Ljava/lang/reflect/Type;)Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-interface {p2}, Ljava/util/Set;->isEmpty()Z

    .line 6
    .line 7
    .line 8
    move-result p2

    .line 9
    const/4 v0, 0x0

    .line 10
    if-nez p2, :cond_0

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const-class p2, Ljava/util/List;

    .line 14
    .line 15
    if-eq p0, p2, :cond_3

    .line 16
    .line 17
    const-class p2, Ljava/util/Collection;

    .line 18
    .line 19
    if-ne p0, p2, :cond_1

    .line 20
    .line 21
    goto :goto_1

    .line 22
    :cond_1
    const-class p2, Ljava/util/Set;

    .line 23
    .line 24
    if-ne p0, p2, :cond_2

    .line 25
    .line 26
    sget-object p0, Lcom/squareup/moshi/CollectionJsonAdapter;->b:Lcom/squareup/moshi/JsonAdapter$Factory;

    .line 27
    .line 28
    invoke-static {p1}, Lcom/squareup/moshi/Types;->a(Ljava/lang/reflect/Type;)Ljava/lang/reflect/Type;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    sget-object p1, Lax/b;->a:Ljava/util/Set;

    .line 33
    .line 34
    invoke-virtual {p3, p0, p1, v0}, Lcom/squareup/moshi/Moshi;->a(Ljava/lang/reflect/Type;Ljava/util/Set;Ljava/lang/String;)Lcom/squareup/moshi/JsonAdapter;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    new-instance p1, Lcom/squareup/moshi/CollectionJsonAdapter$3;

    .line 39
    .line 40
    invoke-direct {p1, p0}, Lcom/squareup/moshi/CollectionJsonAdapter;-><init>(Lcom/squareup/moshi/JsonAdapter;)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {p1}, Lcom/squareup/moshi/JsonAdapter;->d()Lax/a;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0

    .line 48
    :cond_2
    :goto_0
    return-object v0

    .line 49
    :cond_3
    :goto_1
    sget-object p0, Lcom/squareup/moshi/CollectionJsonAdapter;->b:Lcom/squareup/moshi/JsonAdapter$Factory;

    .line 50
    .line 51
    invoke-static {p1}, Lcom/squareup/moshi/Types;->a(Ljava/lang/reflect/Type;)Ljava/lang/reflect/Type;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    sget-object p1, Lax/b;->a:Ljava/util/Set;

    .line 56
    .line 57
    invoke-virtual {p3, p0, p1, v0}, Lcom/squareup/moshi/Moshi;->a(Ljava/lang/reflect/Type;Ljava/util/Set;Ljava/lang/String;)Lcom/squareup/moshi/JsonAdapter;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    new-instance p1, Lcom/squareup/moshi/CollectionJsonAdapter$2;

    .line 62
    .line 63
    invoke-direct {p1, p0}, Lcom/squareup/moshi/CollectionJsonAdapter;-><init>(Lcom/squareup/moshi/JsonAdapter;)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {p1}, Lcom/squareup/moshi/JsonAdapter;->d()Lax/a;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    return-object p0
.end method
