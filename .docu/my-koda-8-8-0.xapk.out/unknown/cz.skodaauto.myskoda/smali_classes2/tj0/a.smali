.class public final Ltj0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lbd0/c;

.field public final b:Lkf0/o;

.field public final c:Lrj0/a;

.field public final d:Lsf0/a;


# direct methods
.method public constructor <init>(Lbd0/c;Lkf0/o;Lrj0/a;Lsf0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ltj0/a;->a:Lbd0/c;

    .line 5
    .line 6
    iput-object p2, p0, Ltj0/a;->b:Lkf0/o;

    .line 7
    .line 8
    iput-object p3, p0, Ltj0/a;->c:Lrj0/a;

    .line 9
    .line 10
    iput-object p4, p0, Ltj0/a;->d:Lsf0/a;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 3

    .line 1
    new-instance v0, Lr60/t;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/16 v2, 0x11

    .line 5
    .line 6
    invoke-direct {v0, p0, v1, v2}, Lr60/t;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 7
    .line 8
    .line 9
    new-instance p0, Lyy0/m1;

    .line 10
    .line 11
    invoke-direct {p0, v0}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 12
    .line 13
    .line 14
    return-object p0
.end method
