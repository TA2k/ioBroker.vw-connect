.class public final Lwo0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lzo0/l;


# instance fields
.field public final a:Lyy0/c2;

.field public final b:Lrz/k;


# direct methods
.method public constructor <init>()V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iput-object v0, p0, Lwo0/b;->a:Lyy0/c2;

    .line 10
    .line 11
    new-instance v1, Lrz/k;

    .line 12
    .line 13
    const/16 v2, 0x15

    .line 14
    .line 15
    invoke-direct {v1, v0, v2}, Lrz/k;-><init>(Lyy0/i;I)V

    .line 16
    .line 17
    .line 18
    iput-object v1, p0, Lwo0/b;->b:Lrz/k;

    .line 19
    .line 20
    return-void
.end method
