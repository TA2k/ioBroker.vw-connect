.class public final Lx81/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final e:Lv71/b;


# instance fields
.field public final a:Leb/j0;

.field public b:Lv71/b;

.field public c:Ljava/lang/Integer;

.field public d:Lw71/b;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    sget-object v0, Lv71/b;->i:Lv71/b;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-static {v0, v1}, Lv71/b;->a(Lv71/b;Z)Lv71/b;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    sput-object v0, Lx81/a;->e:Lv71/b;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>(Ll71/z;)V
    .locals 2

    .line 1
    new-instance v0, Lq81/c;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, p1, v1}, Lq81/c;-><init>(Ll71/z;I)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lx81/a;->a:Leb/j0;

    .line 11
    .line 12
    return-void
.end method
