.class public final Lg1/f2;
.super Lx2/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/c2;


# static fields
.field public static final s:Let/d;


# instance fields
.field public r:Z


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Let/d;

    .line 2
    .line 3
    const/4 v1, 0x6

    .line 4
    invoke-direct {v0, v1}, Let/d;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lg1/f2;->s:Let/d;

    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final g()Ljava/lang/Object;
    .locals 0

    .line 1
    sget-object p0, Lg1/f2;->s:Let/d;

    .line 2
    .line 3
    return-object p0
.end method
