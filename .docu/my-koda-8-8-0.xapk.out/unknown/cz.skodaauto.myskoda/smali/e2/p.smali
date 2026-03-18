.class public abstract Le2/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ll2/u2;

.field public static final b:La71/c;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ldc/a;

    .line 2
    .line 3
    const/16 v1, 0x11

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ldc/a;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Ll2/u2;

    .line 9
    .line 10
    invoke-direct {v1, v0}, Ll2/s1;-><init>(Lay0/a;)V

    .line 11
    .line 12
    .line 13
    sput-object v1, Le2/p;->a:Ll2/u2;

    .line 14
    .line 15
    new-instance v0, La71/c;

    .line 16
    .line 17
    const/4 v1, 0x2

    .line 18
    invoke-direct {v0, v1}, La71/c;-><init>(I)V

    .line 19
    .line 20
    .line 21
    sput-object v0, Le2/p;->b:La71/c;

    .line 22
    .line 23
    return-void
.end method
