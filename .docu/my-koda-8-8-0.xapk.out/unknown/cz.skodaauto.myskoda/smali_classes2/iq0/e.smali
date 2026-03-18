.class public final Liq0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Landroid/content/Context;

.field public final b:Lfq0/a;


# direct methods
.method public constructor <init>(Landroid/content/Context;Lfq0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Liq0/e;->a:Landroid/content/Context;

    .line 5
    .line 6
    iput-object p2, p0, Liq0/e;->b:Lfq0/a;

    .line 7
    .line 8
    return-void
.end method

.method public static a(Landroid/content/Intent;)Landroid/content/Intent;
    .locals 1

    .line 1
    const-string v0, ""

    .line 2
    .line 3
    invoke-static {p0, v0}, Landroid/content/Intent;->createChooser(Landroid/content/Intent;Ljava/lang/CharSequence;)Landroid/content/Intent;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const/high16 v0, 0x10000000

    .line 8
    .line 9
    invoke-virtual {p0, v0}, Landroid/content/Intent;->setFlags(I)Landroid/content/Intent;

    .line 10
    .line 11
    .line 12
    return-object p0
.end method
