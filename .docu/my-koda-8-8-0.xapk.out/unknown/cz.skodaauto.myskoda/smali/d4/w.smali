.class public abstract Ld4/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ld4/z;

.field public static final b:Ld4/z;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Ld4/z;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    sget-object v2, Ld4/u;->v:Ld4/u;

    .line 5
    .line 6
    const-string v3, "TestTagsAsResourceId"

    .line 7
    .line 8
    invoke-direct {v0, v3, v1, v2}, Ld4/z;-><init>(Ljava/lang/String;ZLay0/n;)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Ld4/w;->a:Ld4/z;

    .line 12
    .line 13
    sget-object v0, Ld4/u;->u:Ld4/u;

    .line 14
    .line 15
    new-instance v1, Ld4/z;

    .line 16
    .line 17
    const/4 v2, 0x1

    .line 18
    const-string v3, "AccessibilityClassName"

    .line 19
    .line 20
    invoke-direct {v1, v3, v2, v0}, Ld4/z;-><init>(Ljava/lang/String;ZLay0/n;)V

    .line 21
    .line 22
    .line 23
    sput-object v1, Ld4/w;->b:Ld4/z;

    .line 24
    .line 25
    return-void
.end method
