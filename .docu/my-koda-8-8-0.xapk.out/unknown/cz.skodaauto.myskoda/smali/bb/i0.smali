.class public abstract Lbb/i0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lbb/b;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lbb/b;

    .line 2
    .line 3
    const-string v1, "translationAlpha"

    .line 4
    .line 5
    const/4 v2, 0x5

    .line 6
    const-class v3, Ljava/lang/Float;

    .line 7
    .line 8
    invoke-direct {v0, v2, v1, v3}, Lbb/b;-><init>(ILjava/lang/String;Ljava/lang/Class;)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Lbb/i0;->a:Lbb/b;

    .line 12
    .line 13
    new-instance v0, Lbb/b;

    .line 14
    .line 15
    const-string v1, "clipBounds"

    .line 16
    .line 17
    const/4 v2, 0x6

    .line 18
    const-class v3, Landroid/graphics/Rect;

    .line 19
    .line 20
    invoke-direct {v0, v2, v1, v3}, Lbb/b;-><init>(ILjava/lang/String;Ljava/lang/Class;)V

    .line 21
    .line 22
    .line 23
    return-void
.end method
