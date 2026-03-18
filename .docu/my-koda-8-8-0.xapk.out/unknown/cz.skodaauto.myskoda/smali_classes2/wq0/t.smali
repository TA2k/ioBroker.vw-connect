.class public final Lwq0/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lwq0/v;


# direct methods
.method public constructor <init>(Lwq0/v;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lwq0/t;->a:Lwq0/v;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object p0, p0, Lwq0/t;->a:Lwq0/v;

    .line 2
    .line 3
    invoke-virtual {p0}, Lwq0/v;->invoke()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lyy0/i;

    .line 8
    .line 9
    new-instance v0, Lrz/k;

    .line 10
    .line 11
    const/16 v1, 0x10

    .line 12
    .line 13
    invoke-direct {v0, p0, v1}, Lrz/k;-><init>(Lyy0/i;I)V

    .line 14
    .line 15
    .line 16
    return-object v0
.end method
