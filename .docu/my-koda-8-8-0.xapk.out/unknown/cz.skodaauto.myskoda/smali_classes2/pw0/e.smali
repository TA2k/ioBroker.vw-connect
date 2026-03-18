.class public abstract Lpw0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ldx0/a;

.field public static final b:Ldx0/a;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Ldx0/a;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    const/16 v2, 0x3e8

    .line 5
    .line 6
    invoke-direct {v0, v2, v1}, Ldx0/a;-><init>(II)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lpw0/e;->a:Ldx0/a;

    .line 10
    .line 11
    new-instance v0, Ldx0/a;

    .line 12
    .line 13
    const/4 v1, 0x1

    .line 14
    invoke-direct {v0, v2, v1}, Ldx0/a;-><init>(II)V

    .line 15
    .line 16
    .line 17
    sput-object v0, Lpw0/e;->b:Ldx0/a;

    .line 18
    .line 19
    return-void
.end method
