.class public final Lcom/google/firebase/messaging/i0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Landroid/content/Intent;

.field public final b:Laq/k;


# direct methods
.method public constructor <init>(Landroid/content/Intent;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Laq/k;

    .line 5
    .line 6
    invoke-direct {v0}, Laq/k;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lcom/google/firebase/messaging/i0;->b:Laq/k;

    .line 10
    .line 11
    iput-object p1, p0, Lcom/google/firebase/messaging/i0;->a:Landroid/content/Intent;

    .line 12
    .line 13
    return-void
.end method
