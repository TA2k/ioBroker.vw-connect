.class final Lcom/squareup/moshi/StandardJsonAdapters$ObjectJsonAdapter;
.super Lcom/squareup/moshi/JsonAdapter;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/squareup/moshi/StandardJsonAdapters;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "ObjectJsonAdapter"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lcom/squareup/moshi/JsonAdapter<",
        "Ljava/lang/Object;",
        ">;"
    }
.end annotation


# instance fields
.field public final a:Lcom/squareup/moshi/Moshi;

.field public final b:Lcom/squareup/moshi/JsonAdapter;

.field public final c:Lcom/squareup/moshi/JsonAdapter;

.field public final d:Lcom/squareup/moshi/JsonAdapter;

.field public final e:Lcom/squareup/moshi/JsonAdapter;

.field public final f:Lcom/squareup/moshi/JsonAdapter;


# direct methods
.method public constructor <init>(Lcom/squareup/moshi/Moshi;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Lcom/squareup/moshi/JsonAdapter;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/squareup/moshi/StandardJsonAdapters$ObjectJsonAdapter;->a:Lcom/squareup/moshi/Moshi;

    .line 5
    .line 6
    sget-object v0, Lax/b;->a:Ljava/util/Set;

    .line 7
    .line 8
    const-class v1, Ljava/util/List;

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    invoke-virtual {p1, v1, v0, v2}, Lcom/squareup/moshi/Moshi;->a(Ljava/lang/reflect/Type;Ljava/util/Set;Ljava/lang/String;)Lcom/squareup/moshi/JsonAdapter;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    iput-object v1, p0, Lcom/squareup/moshi/StandardJsonAdapters$ObjectJsonAdapter;->b:Lcom/squareup/moshi/JsonAdapter;

    .line 16
    .line 17
    const-class v1, Ljava/util/Map;

    .line 18
    .line 19
    invoke-virtual {p1, v1, v0, v2}, Lcom/squareup/moshi/Moshi;->a(Ljava/lang/reflect/Type;Ljava/util/Set;Ljava/lang/String;)Lcom/squareup/moshi/JsonAdapter;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    iput-object v1, p0, Lcom/squareup/moshi/StandardJsonAdapters$ObjectJsonAdapter;->c:Lcom/squareup/moshi/JsonAdapter;

    .line 24
    .line 25
    const-class v1, Ljava/lang/String;

    .line 26
    .line 27
    invoke-virtual {p1, v1, v0, v2}, Lcom/squareup/moshi/Moshi;->a(Ljava/lang/reflect/Type;Ljava/util/Set;Ljava/lang/String;)Lcom/squareup/moshi/JsonAdapter;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    iput-object v1, p0, Lcom/squareup/moshi/StandardJsonAdapters$ObjectJsonAdapter;->d:Lcom/squareup/moshi/JsonAdapter;

    .line 32
    .line 33
    const-class v1, Ljava/lang/Double;

    .line 34
    .line 35
    invoke-virtual {p1, v1, v0, v2}, Lcom/squareup/moshi/Moshi;->a(Ljava/lang/reflect/Type;Ljava/util/Set;Ljava/lang/String;)Lcom/squareup/moshi/JsonAdapter;

    .line 36
    .line 37
    .line 38
    move-result-object v1

    .line 39
    iput-object v1, p0, Lcom/squareup/moshi/StandardJsonAdapters$ObjectJsonAdapter;->e:Lcom/squareup/moshi/JsonAdapter;

    .line 40
    .line 41
    const-class v1, Ljava/lang/Boolean;

    .line 42
    .line 43
    invoke-virtual {p1, v1, v0, v2}, Lcom/squareup/moshi/Moshi;->a(Ljava/lang/reflect/Type;Ljava/util/Set;Ljava/lang/String;)Lcom/squareup/moshi/JsonAdapter;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    iput-object p1, p0, Lcom/squareup/moshi/StandardJsonAdapters$ObjectJsonAdapter;->f:Lcom/squareup/moshi/JsonAdapter;

    .line 48
    .line 49
    return-void
.end method


# virtual methods
.method public final a(Lcom/squareup/moshi/JsonReader;)Ljava/lang/Object;
    .locals 2

    .line 1
    invoke-virtual {p1}, Lcom/squareup/moshi/JsonReader;->T()Lcom/squareup/moshi/JsonReader$Token;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_5

    .line 10
    .line 11
    const/4 v1, 0x2

    .line 12
    if-eq v0, v1, :cond_4

    .line 13
    .line 14
    const/4 v1, 0x5

    .line 15
    if-eq v0, v1, :cond_3

    .line 16
    .line 17
    const/4 v1, 0x6

    .line 18
    if-eq v0, v1, :cond_2

    .line 19
    .line 20
    const/4 v1, 0x7

    .line 21
    if-eq v0, v1, :cond_1

    .line 22
    .line 23
    const/16 p0, 0x8

    .line 24
    .line 25
    if-ne v0, p0, :cond_0

    .line 26
    .line 27
    invoke-virtual {p1}, Lcom/squareup/moshi/JsonReader;->E()V

    .line 28
    .line 29
    .line 30
    const/4 p0, 0x0

    .line 31
    return-object p0

    .line 32
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 33
    .line 34
    new-instance v0, Ljava/lang/StringBuilder;

    .line 35
    .line 36
    const-string v1, "Expected a value but was "

    .line 37
    .line 38
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {p1}, Lcom/squareup/moshi/JsonReader;->T()Lcom/squareup/moshi/JsonReader$Token;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    const-string v1, " at path "

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    invoke-virtual {p1}, Lcom/squareup/moshi/JsonReader;->g()Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    throw p0

    .line 68
    :cond_1
    iget-object p0, p0, Lcom/squareup/moshi/StandardJsonAdapters$ObjectJsonAdapter;->f:Lcom/squareup/moshi/JsonAdapter;

    .line 69
    .line 70
    invoke-virtual {p0, p1}, Lcom/squareup/moshi/JsonAdapter;->a(Lcom/squareup/moshi/JsonReader;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    return-object p0

    .line 75
    :cond_2
    iget-object p0, p0, Lcom/squareup/moshi/StandardJsonAdapters$ObjectJsonAdapter;->e:Lcom/squareup/moshi/JsonAdapter;

    .line 76
    .line 77
    invoke-virtual {p0, p1}, Lcom/squareup/moshi/JsonAdapter;->a(Lcom/squareup/moshi/JsonReader;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    return-object p0

    .line 82
    :cond_3
    iget-object p0, p0, Lcom/squareup/moshi/StandardJsonAdapters$ObjectJsonAdapter;->d:Lcom/squareup/moshi/JsonAdapter;

    .line 83
    .line 84
    invoke-virtual {p0, p1}, Lcom/squareup/moshi/JsonAdapter;->a(Lcom/squareup/moshi/JsonReader;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    return-object p0

    .line 89
    :cond_4
    iget-object p0, p0, Lcom/squareup/moshi/StandardJsonAdapters$ObjectJsonAdapter;->c:Lcom/squareup/moshi/JsonAdapter;

    .line 90
    .line 91
    invoke-virtual {p0, p1}, Lcom/squareup/moshi/JsonAdapter;->a(Lcom/squareup/moshi/JsonReader;)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    return-object p0

    .line 96
    :cond_5
    iget-object p0, p0, Lcom/squareup/moshi/StandardJsonAdapters$ObjectJsonAdapter;->b:Lcom/squareup/moshi/JsonAdapter;

    .line 97
    .line 98
    invoke-virtual {p0, p1}, Lcom/squareup/moshi/JsonAdapter;->a(Lcom/squareup/moshi/JsonReader;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    return-object p0
.end method

.method public final e(Lcom/squareup/moshi/JsonWriter;Ljava/lang/Object;)V
    .locals 3

    .line 1
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const-class v1, Ljava/lang/Object;

    .line 6
    .line 7
    if-ne v0, v1, :cond_0

    .line 8
    .line 9
    invoke-virtual {p1}, Lcom/squareup/moshi/JsonWriter;->b()Lcom/squareup/moshi/JsonWriter;

    .line 10
    .line 11
    .line 12
    invoke-virtual {p1}, Lcom/squareup/moshi/JsonWriter;->g()Lcom/squareup/moshi/JsonWriter;

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :cond_0
    const-class v1, Ljava/util/Map;

    .line 17
    .line 18
    invoke-virtual {v1, v0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    if-eqz v2, :cond_1

    .line 23
    .line 24
    :goto_0
    move-object v0, v1

    .line 25
    goto :goto_1

    .line 26
    :cond_1
    const-class v1, Ljava/util/Collection;

    .line 27
    .line 28
    invoke-virtual {v1, v0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_2
    :goto_1
    sget-object v1, Lax/b;->a:Ljava/util/Set;

    .line 36
    .line 37
    const/4 v2, 0x0

    .line 38
    iget-object p0, p0, Lcom/squareup/moshi/StandardJsonAdapters$ObjectJsonAdapter;->a:Lcom/squareup/moshi/Moshi;

    .line 39
    .line 40
    invoke-virtual {p0, v0, v1, v2}, Lcom/squareup/moshi/Moshi;->a(Ljava/lang/reflect/Type;Ljava/util/Set;Ljava/lang/String;)Lcom/squareup/moshi/JsonAdapter;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    invoke-virtual {p0, p1, p2}, Lcom/squareup/moshi/JsonAdapter;->e(Lcom/squareup/moshi/JsonWriter;Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "JsonAdapter(Object)"

    .line 2
    .line 3
    return-object p0
.end method
