.class public final Lx41/a1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic a:Lx41/a1;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lx41/a1;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lx41/a1;->a:Lx41/a1;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final serializer()Lqz0/a;
    .locals 6
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lqz0/a;"
        }
    .end annotation

    .line 1
    new-instance v0, Lqz0/f;

    .line 2
    .line 3
    sget-object p0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 4
    .line 5
    const-class v1, Lx41/h1;

    .line 6
    .line 7
    invoke-virtual {p0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 8
    .line 9
    .line 10
    move-result-object v2

    .line 11
    const-class v1, Lx41/d1;

    .line 12
    .line 13
    invoke-virtual {p0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    const-class v3, Lx41/g1;

    .line 18
    .line 19
    invoke-virtual {p0, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    const/4 v3, 0x2

    .line 24
    move v4, v3

    .line 25
    new-array v3, v4, [Lhy0/d;

    .line 26
    .line 27
    const/4 v5, 0x0

    .line 28
    aput-object v1, v3, v5

    .line 29
    .line 30
    const/4 v1, 0x1

    .line 31
    aput-object p0, v3, v1

    .line 32
    .line 33
    new-array v4, v4, [Lqz0/a;

    .line 34
    .line 35
    sget-object p0, Lx41/b1;->a:Lx41/b1;

    .line 36
    .line 37
    aput-object p0, v4, v5

    .line 38
    .line 39
    sget-object p0, Lx41/e1;->a:Lx41/e1;

    .line 40
    .line 41
    aput-object p0, v4, v1

    .line 42
    .line 43
    new-array v5, v5, [Ljava/lang/annotation/Annotation;

    .line 44
    .line 45
    const-string v1, "technology.cariad.cat.car2phone.pairing.PairingV0"

    .line 46
    .line 47
    invoke-direct/range {v0 .. v5}, Lqz0/f;-><init>(Ljava/lang/String;Lhy0/d;[Lhy0/d;[Lqz0/a;[Ljava/lang/annotation/Annotation;)V

    .line 48
    .line 49
    .line 50
    return-object v0
.end method
