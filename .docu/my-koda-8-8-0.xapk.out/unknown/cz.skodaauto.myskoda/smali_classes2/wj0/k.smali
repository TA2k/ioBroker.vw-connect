.class public final Lwj0/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lwj0/a;


# direct methods
.method public constructor <init>(Lwj0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lwj0/k;->a:Lwj0/a;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object p0, p0, Lwj0/k;->a:Lwj0/a;

    .line 2
    .line 3
    check-cast p0, Luj0/c;

    .line 4
    .line 5
    iget-object p0, p0, Luj0/c;->d:Lyy0/l1;

    .line 6
    .line 7
    new-instance v0, Lrz/k;

    .line 8
    .line 9
    const/16 v1, 0xb

    .line 10
    .line 11
    invoke-direct {v0, p0, v1}, Lrz/k;-><init>(Lyy0/i;I)V

    .line 12
    .line 13
    .line 14
    return-object v0
.end method
