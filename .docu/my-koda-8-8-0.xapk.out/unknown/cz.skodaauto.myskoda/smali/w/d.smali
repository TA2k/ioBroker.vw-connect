.class public final Lw/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lw/b;


# static fields
.field public static final a:Lpv/g;

.field public static final b:Ljava/util/Set;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lpv/g;

    .line 2
    .line 3
    new-instance v1, Lw/d;

    .line 4
    .line 5
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    const/16 v2, 0x13

    .line 9
    .line 10
    invoke-direct {v0, v1, v2}, Lpv/g;-><init>(Ljava/lang/Object;I)V

    .line 11
    .line 12
    .line 13
    sput-object v0, Lw/d;->a:Lpv/g;

    .line 14
    .line 15
    sget-object v0, Lb0/y;->d:Lb0/y;

    .line 16
    .line 17
    invoke-static {v0}, Ljava/util/Collections;->singleton(Ljava/lang/Object;)Ljava/util/Set;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    sput-object v0, Lw/d;->b:Ljava/util/Set;

    .line 22
    .line 23
    return-void
.end method


# virtual methods
.method public final a()Landroid/hardware/camera2/params/DynamicRangeProfiles;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method

.method public final b(Lb0/y;)Ljava/util/Set;
    .locals 2

    .line 1
    sget-object p0, Lb0/y;->d:Lb0/y;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lb0/y;->equals(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    new-instance v0, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v1, "DynamicRange is not supported: "

    .line 10
    .line 11
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    invoke-static {p0, p1}, Ljp/ed;->b(ZLjava/lang/String;)V

    .line 22
    .line 23
    .line 24
    sget-object p0, Lw/d;->b:Ljava/util/Set;

    .line 25
    .line 26
    return-object p0
.end method

.method public final d()Ljava/util/Set;
    .locals 0

    .line 1
    sget-object p0, Lw/d;->b:Ljava/util/Set;

    .line 2
    .line 3
    return-object p0
.end method
