.class public final Lxw/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:C

.field public b:C

.field public c:C

.field public d:C


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/16 v0, 0x7b

    .line 5
    .line 6
    iput-char v0, p0, Lxw/i;->a:C

    .line 7
    .line 8
    const/16 v1, 0x7d

    .line 9
    .line 10
    iput-char v1, p0, Lxw/i;->b:C

    .line 11
    .line 12
    iput-char v0, p0, Lxw/i;->c:C

    .line 13
    .line 14
    iput-char v1, p0, Lxw/i;->d:C

    .line 15
    .line 16
    return-void
.end method

.method public static a(Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, "Invalid delimiter configuration \'"

    .line 2
    .line 3
    const-string v1, "\'. Must be of the form {{=1 2=}} or {{=12 34=}} where 1, 2, 3 and 4 are delimiter chars."

    .line 4
    .line 5
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
