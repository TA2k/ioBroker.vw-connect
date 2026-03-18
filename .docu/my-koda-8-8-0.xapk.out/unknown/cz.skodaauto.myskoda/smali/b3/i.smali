.class public final Lb3/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lb3/b;


# static fields
.field public static final d:Lb3/i;

.field public static final e:Lt4/m;

.field public static final f:Lt4/d;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lb3/i;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lb3/i;->d:Lb3/i;

    .line 7
    .line 8
    sget-object v0, Lt4/m;->d:Lt4/m;

    .line 9
    .line 10
    sput-object v0, Lb3/i;->e:Lt4/m;

    .line 11
    .line 12
    new-instance v0, Lt4/d;

    .line 13
    .line 14
    const/high16 v1, 0x3f800000    # 1.0f

    .line 15
    .line 16
    invoke-direct {v0, v1, v1}, Lt4/d;-><init>(FF)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Lb3/i;->f:Lt4/d;

    .line 20
    .line 21
    return-void
.end method


# virtual methods
.method public final a()Lt4/c;
    .locals 0

    .line 1
    sget-object p0, Lb3/i;->f:Lt4/d;

    .line 2
    .line 3
    return-object p0
.end method

.method public final e()J
    .locals 2

    .line 1
    const-wide v0, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 2
    .line 3
    .line 4
    .line 5
    .line 6
    return-wide v0
.end method

.method public final getLayoutDirection()Lt4/m;
    .locals 0

    .line 1
    sget-object p0, Lb3/i;->e:Lt4/m;

    .line 2
    .line 3
    return-object p0
.end method
