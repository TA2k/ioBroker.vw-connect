.class public final Lhu/a1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lhu/a1;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lhu/a1;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lhu/a1;->a:Lhu/a1;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a()Lhu/z0;
    .locals 2

    .line 1
    new-instance p0, Lhu/z0;

    .line 2
    .line 3
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    invoke-direct {p0, v0, v1}, Lhu/z0;-><init>(J)V

    .line 8
    .line 9
    .line 10
    return-object p0
.end method
