.class public Lcom/contoworks/kontocloud/apiclient/gson/LocalDateConverter;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/gson/s;
.implements Lcom/google/gson/m;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lcom/google/gson/s;",
        "Lcom/google/gson/m;"
    }
.end annotation


# static fields
.field public static final a:Lr11/b;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "yyyy-MM-dd"

    .line 2
    .line 3
    invoke-static {v0}, Lr11/a;->a(Ljava/lang/String;)Lr11/b;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/contoworks/kontocloud/apiclient/gson/LocalDateConverter;->a:Lr11/b;

    .line 8
    .line 9
    return-void
.end method

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
.method public final a(Ljava/lang/Object;Ljava/lang/reflect/Type;)Lcom/google/gson/r;
    .locals 0

    .line 1
    check-cast p1, Ln11/k;

    .line 2
    .line 3
    new-instance p0, Lcom/google/gson/r;

    .line 4
    .line 5
    sget-object p2, Lcom/contoworks/kontocloud/apiclient/gson/LocalDateConverter;->a:Lr11/b;

    .line 6
    .line 7
    invoke-virtual {p2, p1}, Lr11/b;->c(Lo11/b;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    invoke-direct {p0, p1}, Lcom/google/gson/r;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    return-object p0
.end method

.method public final b(Lcom/google/gson/n;Ljava/lang/reflect/Type;)Ljava/lang/Object;
    .locals 2

    .line 1
    invoke-virtual {p1}, Lcom/google/gson/n;->e()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-eqz p0, :cond_1

    .line 6
    .line 7
    invoke-virtual {p1}, Lcom/google/gson/n;->e()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    sget-object p0, Lcom/contoworks/kontocloud/apiclient/gson/LocalDateConverter;->a:Lr11/b;

    .line 19
    .line 20
    invoke-virtual {p1}, Lcom/google/gson/n;->e()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    invoke-virtual {p0, p1}, Lr11/b;->a(Ljava/lang/String;)Ln11/l;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    new-instance p1, Ln11/k;

    .line 29
    .line 30
    iget-wide v0, p0, Ln11/l;->d:J

    .line 31
    .line 32
    iget-object p0, p0, Ln11/l;->e:Ljp/u1;

    .line 33
    .line 34
    invoke-direct {p1, v0, v1, p0}, Ln11/k;-><init>(JLjp/u1;)V

    .line 35
    .line 36
    .line 37
    return-object p1

    .line 38
    :cond_1
    :goto_0
    const/4 p0, 0x0

    .line 39
    return-object p0
.end method
