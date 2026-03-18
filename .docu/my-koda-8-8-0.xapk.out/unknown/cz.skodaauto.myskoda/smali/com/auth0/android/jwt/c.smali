.class public final Lcom/auth0/android/jwt/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable;


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lcom/auth0/android/jwt/c;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public final d:Ljava/lang/String;

.field public final e:Lcom/auth0/android/jwt/d;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lsp/w;

    .line 2
    .line 3
    const/16 v1, 0xf

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lsp/w;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lcom/auth0/android/jwt/c;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;)V
    .locals 8

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const-string v0, "\\."

    .line 5
    .line 6
    invoke-virtual {p1, v0}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    array-length v1, v0

    .line 11
    const/4 v2, 0x1

    .line 12
    const/4 v3, 0x0

    .line 13
    const/4 v4, 0x3

    .line 14
    const-string v5, "."

    .line 15
    .line 16
    const/4 v6, 0x2

    .line 17
    if-ne v1, v6, :cond_0

    .line 18
    .line 19
    invoke-virtual {p1, v5}, Ljava/lang/String;->endsWith(Ljava/lang/String;)Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-eqz v1, :cond_0

    .line 24
    .line 25
    new-array v1, v4, [Ljava/lang/String;

    .line 26
    .line 27
    aget-object v7, v0, v3

    .line 28
    .line 29
    aput-object v7, v1, v3

    .line 30
    .line 31
    aget-object v0, v0, v2

    .line 32
    .line 33
    aput-object v0, v1, v2

    .line 34
    .line 35
    const-string v0, ""

    .line 36
    .line 37
    aput-object v0, v1, v6

    .line 38
    .line 39
    move-object v0, v1

    .line 40
    :cond_0
    array-length v1, v0

    .line 41
    if-ne v1, v4, :cond_1

    .line 42
    .line 43
    new-instance v1, Lcom/auth0/android/jwt/JWT$2;

    .line 44
    .line 45
    invoke-direct {v1}, Lcom/google/gson/reflect/TypeToken;-><init>()V

    .line 46
    .line 47
    .line 48
    invoke-virtual {v1}, Lcom/google/gson/reflect/TypeToken;->getType()Ljava/lang/reflect/Type;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    aget-object v3, v0, v3

    .line 53
    .line 54
    invoke-static {v3}, Lcom/auth0/android/jwt/c;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v3

    .line 58
    invoke-static {v3, v1}, Lcom/auth0/android/jwt/c;->c(Ljava/lang/String;Ljava/lang/reflect/Type;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v1

    .line 62
    check-cast v1, Ljava/util/Map;

    .line 63
    .line 64
    aget-object v1, v0, v2

    .line 65
    .line 66
    invoke-static {v1}, Lcom/auth0/android/jwt/c;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v1

    .line 70
    const-class v2, Lcom/auth0/android/jwt/d;

    .line 71
    .line 72
    invoke-static {v1, v2}, Lcom/auth0/android/jwt/c;->c(Ljava/lang/String;Ljava/lang/reflect/Type;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v1

    .line 76
    check-cast v1, Lcom/auth0/android/jwt/d;

    .line 77
    .line 78
    iput-object v1, p0, Lcom/auth0/android/jwt/c;->e:Lcom/auth0/android/jwt/d;

    .line 79
    .line 80
    aget-object v0, v0, v6

    .line 81
    .line 82
    iput-object p1, p0, Lcom/auth0/android/jwt/c;->d:Ljava/lang/String;

    .line 83
    .line 84
    return-void

    .line 85
    :cond_1
    new-instance p0, La8/r0;

    .line 86
    .line 87
    array-length p1, v0

    .line 88
    const-string v0, "The token was expected to have 3 parts, but got "

    .line 89
    .line 90
    invoke-static {v0, p1, v5}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object p1

    .line 94
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    throw p0
.end method

.method public static a(Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    const/16 v0, 0xb

    .line 2
    .line 3
    :try_start_0
    invoke-static {p0, v0}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    new-instance v0, Ljava/lang/String;

    .line 8
    .line 9
    invoke-static {}, Ljava/nio/charset/Charset;->defaultCharset()Ljava/nio/charset/Charset;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    invoke-direct {v0, p0, v1}, Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 14
    .line 15
    .line 16
    return-object v0

    .line 17
    :catch_0
    move-exception p0

    .line 18
    new-instance v0, La8/r0;

    .line 19
    .line 20
    const-string v1, "Received bytes didn\'t correspond to a valid Base64 encoded string."

    .line 21
    .line 22
    invoke-direct {v0, v1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 23
    .line 24
    .line 25
    throw v0
.end method

.method public static c(Ljava/lang/String;Ljava/lang/reflect/Type;)Ljava/lang/Object;
    .locals 3

    .line 1
    :try_start_0
    new-instance v0, Lcom/google/gson/k;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/google/gson/k;-><init>()V

    .line 4
    .line 5
    .line 6
    const-class v1, Lcom/auth0/android/jwt/d;

    .line 7
    .line 8
    new-instance v2, Lcom/auth0/android/jwt/JWTDeserializer;

    .line 9
    .line 10
    invoke-direct {v2}, Lcom/auth0/android/jwt/JWTDeserializer;-><init>()V

    .line 11
    .line 12
    .line 13
    invoke-virtual {v0, v1, v2}, Lcom/google/gson/k;->b(Ljava/lang/Class;Lcom/google/gson/m;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0}, Lcom/google/gson/k;->a()Lcom/google/gson/j;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-static {p1}, Lcom/google/gson/reflect/TypeToken;->get(Ljava/lang/reflect/Type;)Lcom/google/gson/reflect/TypeToken;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    invoke-virtual {v0, p0, p1}, Lcom/google/gson/j;->b(Ljava/lang/String;Lcom/google/gson/reflect/TypeToken;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 28
    return-object p0

    .line 29
    :catch_0
    move-exception p0

    .line 30
    new-instance p1, La8/r0;

    .line 31
    .line 32
    const-string v0, "The token\'s payload had an invalid JSON format."

    .line 33
    .line 34
    invoke-direct {p1, v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 35
    .line 36
    .line 37
    throw p1
.end method


# virtual methods
.method public final b(Ljava/lang/String;)Lcom/auth0/android/jwt/a;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/auth0/android/jwt/c;->e:Lcom/auth0/android/jwt/d;

    .line 2
    .line 3
    iget-object p0, p0, Lcom/auth0/android/jwt/d;->b:Ljava/util/Map;

    .line 4
    .line 5
    invoke-interface {p0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lcom/auth0/android/jwt/a;

    .line 10
    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    return-object p0

    .line 14
    :cond_0
    new-instance p0, Lcom/auth0/android/jwt/a;

    .line 15
    .line 16
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 17
    .line 18
    .line 19
    return-object p0
.end method

.method public final describeContents()I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/auth0/android/jwt/c;->d:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/auth0/android/jwt/c;->d:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {p1, p0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
