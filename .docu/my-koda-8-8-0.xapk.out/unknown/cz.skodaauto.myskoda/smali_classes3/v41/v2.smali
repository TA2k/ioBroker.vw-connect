.class public final Lv41/v2;
.super Lu41/d;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lqz0/g;
    with = Lu41/e;
.end annotation


# static fields
.field public static final INSTANCE:Lv41/v2;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lv41/v2;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lv41/v2;->INSTANCE:Lv41/v2;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "trafficSigns"

    .line 2
    .line 3
    return-object p0
.end method

.method public final serializer()Lqz0/a;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lqz0/a;"
        }
    .end annotation

    .line 1
    sget-object p0, Lu41/e;->a:Lu41/e;

    .line 2
    .line 3
    return-object p0
.end method
