.class final Lretrofit2/converter/moshi/MoshiRequestBodyConverter;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lretrofit2/Converter;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;",
        "Lretrofit2/Converter<",
        "TT;",
        "Ld01/r0;",
        ">;"
    }
.end annotation


# static fields
.field public static final e:Ld01/d0;


# instance fields
.field public final d:Lcom/squareup/moshi/JsonAdapter;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Ld01/d0;->e:Lly0/n;

    .line 2
    .line 3
    const-string v0, "application/json; charset=UTF-8"

    .line 4
    .line 5
    invoke-static {v0}, Ljp/ue;->c(Ljava/lang/String;)Ld01/d0;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    sput-object v0, Lretrofit2/converter/moshi/MoshiRequestBodyConverter;->e:Ld01/d0;

    .line 10
    .line 11
    return-void
.end method

.method public constructor <init>(Lcom/squareup/moshi/JsonAdapter;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lretrofit2/converter/moshi/MoshiRequestBodyConverter;->d:Lcom/squareup/moshi/JsonAdapter;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final j(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    new-instance v0, Lu01/f;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-static {v0}, Lcom/squareup/moshi/JsonWriter;->l(Lu01/f;)Lcom/squareup/moshi/JsonWriter;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    iget-object p0, p0, Lretrofit2/converter/moshi/MoshiRequestBodyConverter;->d:Lcom/squareup/moshi/JsonAdapter;

    .line 11
    .line 12
    invoke-virtual {p0, v1, p1}, Lcom/squareup/moshi/JsonAdapter;->e(Lcom/squareup/moshi/JsonWriter;Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    iget-wide p0, v0, Lu01/f;->e:J

    .line 16
    .line 17
    invoke-virtual {v0, p0, p1}, Lu01/f;->S(J)Lu01/i;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    sget-object p1, Lretrofit2/converter/moshi/MoshiRequestBodyConverter;->e:Ld01/d0;

    .line 22
    .line 23
    invoke-static {p1, p0}, Ld01/r0;->create(Ld01/d0;Lu01/i;)Ld01/r0;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0
.end method
